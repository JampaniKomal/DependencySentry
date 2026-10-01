"""Run an audit: manifest -> dependency graph -> advisories and abandonware."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import manifest as manifest_mod
from .clients import OSV, SEVERITY_ORDER, Advisory, PyPI, now
from .resolve import Graph, ResolutionError, resolve_approximately, resolve_with_pip


@dataclass
class Settings:
    mode: str = "exact"  # "exact" (pip's resolver, falling back to approximate) or "approximate"
    abandoned_after_days: int = 730  # 0 turns the check off
    max_depth: int = 6  # approximate mode only


@dataclass
class AuditReport:
    manifest: manifest_mod.Manifest
    graph: Graph
    advisories: dict[str, list[Advisory]] = field(default_factory=dict)  # canonical name -> advisories
    abandoned: dict[str, datetime] = field(default_factory=dict)  # canonical name -> last release
    notes: list[str] = field(default_factory=list)
    when: datetime = field(default_factory=now)

    def worst(self, key: str) -> str | None:
        advisories = self.advisories.get(key) or []
        return max((a.severity for a in advisories), key=SEVERITY_ORDER.index) if advisories else None

    def count_at_least(self, level: str) -> int:
        floor = SEVERITY_ORDER.index(level)
        return sum(
            1
            for advisories in self.advisories.values()
            for a in advisories
            if SEVERITY_ORDER.index(a.severity) >= floor
        )

    @property
    def vulnerable(self) -> list[str]:
        return [k for k, v in self.advisories.items() if v]


def run(
    path: str,
    settings: Settings | None = None,
    log: Callable[[str], None] = lambda _msg: None,
    pypi: PyPI | None = None,
    osv: OSV | None = None,
    pip_resolve=resolve_with_pip,
) -> AuditReport:
    settings = settings or Settings()
    pypi, osv = pypi or PyPI(), osv or OSV()
    manifest = manifest_mod.load(path)
    log(f"[*] {len(manifest.requirements)} requirement(s) in {manifest.path.name}")
    for line, reason in manifest.skipped:
        log(f"[-] skipped '{line}': {reason}")

    notes = []
    graph = None
    if settings.mode == "exact":
        log("[*] Resolving with pip's resolver (dry run, wheels only: no package code is run)...")
        try:
            graph = pip_resolve(manifest)
        except ResolutionError as exc:
            notes.append(f"Exact resolution failed, so versions are approximate: {exc}")
            log(f"[!] {exc}")
    if graph is None:
        log("[*] Resolving approximately from PyPI metadata...")
        graph = resolve_approximately(manifest, pypi, settings.max_depth)
    for warning in graph.warnings:
        log(f"[!] {warning}")
    log(f"[*] {len(graph.packages)} package(s) in the tree ({graph.mode})")

    report = AuditReport(manifest, graph, notes=notes + graph.warnings)
    if not graph.packages:
        return report

    log("[*] Checking OSV.dev for known vulnerabilities...")
    pairs = [(p.key, p.version) for p in graph.packages.values()]
    for (key, _version), ids in osv.query(pairs).items():
        report.advisories[key] = osv.advisories(key, ids) if ids else []
        pkg = graph.packages[key]
        if ids:
            a = report.advisories[key]
            log(f"[VULN] {pkg.name}=={pkg.version}: {len(a)} advisories, worst {report.worst(key)}")
        else:
            log(f"[OK]   {pkg.name}=={pkg.version}")

    if settings.abandoned_after_days:
        cutoff = now() - timedelta(days=settings.abandoned_after_days)
        for key, pkg in graph.packages.items():
            last = pypi.last_release(pkg.name)
            if last and last < cutoff:
                report.abandoned[key] = last
                log(f"[STALE] {pkg.name}: no release since {last:%Y-%m-%d}")
    log(
        f"[*] Done: {len(report.vulnerable)} of {len(graph.packages)} packages have known vulnerabilities"
        f" ({sum(len(v) for v in report.advisories.values())} advisories); {len(report.abandoned)} look abandoned."
    )
    return report
