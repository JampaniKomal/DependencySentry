"""Read the requirements a project declares.

Supports requirements files (comments, line continuations, `-r` includes,
hashes and environment markers; pip options are skipped) and the
`[project] dependencies` of a pyproject.toml. Requirements that cannot be
audited by name and version (editable installs, VCS and URL references) are
reported as skipped rather than silently dropped.
"""

from __future__ import annotations

import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement


@dataclass
class Manifest:
    path: Path
    requirements: list[Requirement] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (line, reason)


def _logical_lines(text: str):
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        yield (buffer + line).strip()
        buffer = ""
    if buffer.strip():
        yield buffer.strip()


def _strip_comment(line: str) -> str:
    # pip treats " #" (whitespace then #) as the start of a comment
    return re.split(r"(^|\s)#", line, maxsplit=1)[0].strip()


def _add(manifest: Manifest, text: str) -> None:
    text = re.sub(r"\s--hash=\S+", "", text).strip()
    if not text:
        return
    if text.startswith(("-e ", "--editable")) or "://" in text.split(";")[0] or text.startswith((".", "/")):
        manifest.skipped.append((text, "editable, local or URL requirement: not audited by name and version"))
        return
    try:
        req = Requirement(text)
    except InvalidRequirement as exc:
        manifest.skipped.append((text, f"not a valid requirement ({exc})"))
        return
    if req.url:
        manifest.skipped.append((text, "direct URL requirement: not audited by name and version"))
        return
    manifest.requirements.append(req)


def _read_requirements(path: Path, manifest: Manifest, seen: set[Path]) -> None:
    path = path.resolve()
    if path in seen:
        return
    seen.add(path)
    for line in _logical_lines(path.read_text(encoding="utf-8-sig")):
        line = _strip_comment(line)
        if not line:
            continue
        include = re.match(r"^(-r|--requirement)[\s=]+(\S+)", line)
        if include:
            target = path.parent / include.group(2)
            if target.exists():
                _read_requirements(target, manifest, seen)
            else:
                manifest.skipped.append((line, "included file not found"))
            continue
        if line.startswith("-") and not line.startswith(("-e", "--editable")):
            continue  # pip options: --index-url, -c constraints, --hash-only lines, ...
        _add(manifest, line)


def load(path: str | Path) -> Manifest:
    path = Path(path)
    manifest = Manifest(path)
    if path.name == "pyproject.toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for text in data.get("project", {}).get("dependencies", []):
            _add(manifest, text)
    else:
        _read_requirements(path, manifest, set())
    return manifest
