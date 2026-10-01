"""Resolve a manifest into the exact set of packages that would be installed.

**Exact mode** asks pip's own resolver: `pip install --dry-run --report`
lists every package pip would install, at the version it would pick, for
this Python and platform, without installing anything. `--only-binary=:all:`
means pip only reads wheel metadata and never runs a package's build code,
which matters when the manifest is untrusted.

**Approximate mode** is the fallback when pip cannot resolve (a package with
no wheel, a conflict, no pip): it walks PyPI's metadata itself, taking the
pinned version if there is one and otherwise the newest release that satisfies
the specifier, and the dependencies of that exact version. It does not
backtrack across conflicts, so the result is labelled approximate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import deque
from dataclasses import dataclass, field

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .manifest import Manifest


class ResolutionError(RuntimeError):
    pass


@dataclass
class Package:
    name: str
    version: str
    direct: bool = False
    requires: list[str] = field(default_factory=list)  # canonical names of dependencies in the graph

    @property
    def key(self) -> str:
        return canonicalize_name(self.name)

    @property
    def purl(self) -> str:
        return f"pkg:pypi/{self.key}@{self.version}"


@dataclass
class Graph:
    packages: dict[str, Package]  # canonical name -> Package
    mode: str  # "exact (pip)" or "approximate"
    environment: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def roots(self) -> list[Package]:
        return [p for p in self.packages.values() if p.direct]


def _applies(req: Requirement, env: dict, extras: set[str]) -> bool:
    if req.marker is None:
        return True
    return any(req.marker.evaluate({**env, "extra": extra}) for extra in (extras or {""}))


def _edges(packages: dict[str, Package], requires_dist: dict[str, list[str]], extras: dict[str, set[str]], env):
    for key, pkg in packages.items():
        for text in requires_dist.get(key) or []:
            try:
                req = Requirement(text)
            except InvalidRequirement:
                continue
            child = canonicalize_name(req.name)
            if child in packages and child != key and _applies(req, env, extras.get(key, set())):
                if child not in pkg.requires:
                    pkg.requires.append(child)


def from_pip_report(report: dict, manifest: Manifest) -> Graph:
    env = report.get("environment") or default_environment()
    direct = {canonicalize_name(r.name) for r in manifest.requirements}
    extras: dict[str, set[str]] = {canonicalize_name(r.name): set(r.extras) for r in manifest.requirements}
    packages: dict[str, Package] = {}
    requires_dist: dict[str, list[str]] = {}
    for item in report.get("install", []):
        meta = item["metadata"]
        key = canonicalize_name(meta["name"])
        packages[key] = Package(meta["name"], meta["version"], direct=key in direct or bool(item.get("requested")))
        requires_dist[key] = meta.get("requires_dist") or []
    # extras requested by one package of another (e.g. "requests[socks]")
    for texts in requires_dist.values():
        for text in texts:
            try:
                req = Requirement(text)
            except InvalidRequirement:
                continue
            if req.extras:
                extras.setdefault(canonicalize_name(req.name), set()).update(req.extras)
    _edges(packages, requires_dist, extras, env)
    return Graph(packages, "exact (pip)", env)


def resolve_with_pip(manifest: Manifest, python: str | None = None, timeout: int = 600) -> Graph:
    if not manifest.requirements:
        return Graph({}, "exact (pip)", default_environment())
    with tempfile.TemporaryDirectory() as tmp:
        req_file = os.path.join(tmp, "requirements.txt")
        report_file = os.path.join(tmp, "report.json")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("\n".join(str(r) for r in manifest.requirements) + "\n")
        cmd = [
            python or sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
            "--only-binary=:all:", "--quiet", "--disable-pip-version-check", "--no-input",
            "--report", report_file, "-r", req_file,
        ]  # fmt: skip
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ResolutionError(f"could not run pip: {exc}") from exc
        if done.returncode != 0 or not os.path.exists(report_file):
            lines = [line for line in (done.stderr or done.stdout).splitlines() if line.strip()]
            raise ResolutionError("pip could not resolve the manifest: " + " ".join(lines[-3:]))
        with open(report_file, encoding="utf-8") as f:
            return from_pip_report(json.load(f), manifest)


def _pick_version(info: dict, req: Requirement) -> str | None:
    pinned = [s.version for s in req.specifier if s.operator in ("==", "===") and "*" not in s.version]
    if pinned:
        return pinned[0]
    candidates = []
    for text, files in (info.get("releases") or {}).items():
        try:
            v = Version(text)
        except InvalidVersion:
            continue
        if v.is_prerelease or not files or all(f.get("yanked") for f in files):
            continue
        if v in req.specifier:
            candidates.append(v)
    return str(max(candidates)) if candidates else None


def resolve_approximately(manifest: Manifest, pypi, max_depth: int = 6) -> Graph:
    env = default_environment()
    graph = Graph({}, "approximate", env)
    extras: dict[str, set[str]] = {}
    requires_dist: dict[str, list[str]] = {}
    queue = deque((req, 0, True) for req in manifest.requirements)
    while queue:
        req, depth, direct = queue.popleft()
        key = canonicalize_name(req.name)
        extras.setdefault(key, set()).update(req.extras)
        if key in graph.packages:
            if direct:
                graph.packages[key].direct = True
            continue
        project = pypi.project(req.name)
        if not project:
            graph.warnings.append(f"{req.name}: not found on PyPI")
            continue
        version = _pick_version(project, req)
        if not version:
            graph.warnings.append(f"{req.name}: no release satisfies '{req.specifier}'")
            continue
        meta = pypi.release(req.name, version) or {}
        graph.packages[key] = Package(project["info"]["name"], version, direct=direct)
        requires_dist[key] = (meta.get("info") or {}).get("requires_dist") or []
        if depth >= max_depth:
            continue
        for text in requires_dist[key]:
            try:
                child = Requirement(text)
            except InvalidRequirement:
                continue
            if _applies(child, env, extras[key]):
                queue.append((child, depth + 1, False))
    _edges(graph.packages, requires_dist, extras, env)
    return graph
