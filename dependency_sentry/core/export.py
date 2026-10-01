"""Export an audit: a CycloneDX 1.6 SBOM, plain JSON, and a text summary."""

from __future__ import annotations

import uuid

from .. import __version__
from .audit import AuditReport

CYCLONEDX_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}


def cyclonedx(report: AuditReport) -> dict:
    """The dependency tree, with known vulnerabilities, as a CycloneDX 1.6 JSON SBOM."""
    packages = report.graph.packages
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "dependency-sentry", "version": __version__}]},
            "component": {"type": "application", "name": report.manifest.path.name, "bom-ref": "root"},
            "properties": [{"name": "dependency-sentry:resolution", "value": report.graph.mode}],
        },
        "components": [
            {
                "type": "library",
                "bom-ref": p.purl,
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                **({"properties": [{"name": "dependency-sentry:direct", "value": "true"}]} if p.direct else {}),
            }
            for p in sorted(packages.values(), key=lambda p: p.key)
        ],
        "dependencies": [{"ref": "root", "dependsOn": sorted(p.purl for p in report.graph.roots())}]
        + [
            {"ref": p.purl, "dependsOn": sorted(packages[c].purl for c in p.requires)}
            for p in sorted(packages.values(), key=lambda p: p.key)
        ],
    }
    vulnerabilities = []
    for key, advisories in sorted(report.advisories.items()):
        pkg = packages[key]
        for a in advisories:
            entry = {
                "bom-ref": f"{a.id}@{pkg.purl}",
                "id": a.id,
                "source": {"name": "OSV", "url": a.url},
                "references": [
                    {"id": alias, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{alias}"}}
                    for alias in a.aliases
                ],
                "ratings": [{"source": {"name": "OSV"}, "severity": CYCLONEDX_SEVERITY.get(a.severity, "unknown")}],
                "description": a.summary,
                "affects": [{"ref": pkg.purl}],
            }
            fix = a.fixed_after(pkg.version)
            if fix:
                entry["recommendation"] = f"Upgrade {pkg.name} to {fix} or later"
            if a.published:
                entry["published"] = a.published
            vulnerabilities.append(entry)
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def to_json(report: AuditReport) -> dict:
    return {
        "manifest": str(report.manifest.path),
        "resolution": report.graph.mode,
        "notes": report.notes,
        "skipped": [{"line": line, "reason": reason} for line, reason in report.manifest.skipped],
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "direct": p.direct,
                "requires": [report.graph.packages[c].name for c in p.requires],
                "last_release": report.abandoned[p.key].date().isoformat() if p.key in report.abandoned else None,
                "advisories": [
                    {
                        "id": a.id,
                        "aliases": a.aliases,
                        "severity": a.severity,
                        "summary": a.summary,
                        "fixed_in": a.fixed_after(p.version),
                        "url": a.url,
                    }
                    for a in report.advisories.get(p.key, [])
                ],
            }
            for p in sorted(report.graph.packages.values(), key=lambda p: (not p.direct, p.key))
        ],
    }


def to_text(report: AuditReport) -> str:
    g = report.graph
    lines = [
        f"Dependency-Sentry {__version__}: {report.manifest.path.name}",
        f"{len(g.packages)} packages ({g.mode}); {len(report.vulnerable)} with known vulnerabilities;"
        f" {len(report.abandoned)} without a release in the configured period",
    ]
    lines += [f"note: {n}" for n in report.notes]
    for line, reason in report.manifest.skipped:
        lines.append(f"skipped: {line} ({reason})")

    def walk(key: str, depth: int, seen: set[str]):
        p = g.packages[key]
        tags = []
        if report.advisories.get(key):
            tags.append(f"{len(report.advisories[key])} advisories, worst {report.worst(key)}")
        if key in report.abandoned:
            tags.append(f"last release {report.abandoned[key]:%Y-%m-%d}")
        suffix = f"  [{'; '.join(tags)}]" if tags else ""
        lines.append(f"{'  ' * depth}{p.name}=={p.version}{suffix}")
        if key in seen:
            return
        for child in p.requires:
            walk(child, depth + 1, seen | {key})

    lines.append("")
    for root in sorted(g.roots(), key=lambda p: p.key):
        walk(root.key, 0, set())
    for key in report.vulnerable:
        p = g.packages[key]
        lines.append(f"\n{p.name}=={p.version}")
        for a in report.advisories[key]:
            fix = a.fixed_after(p.version)
            cve = f" ({', '.join(a.cves)})" if a.cves else ""
            lines.append(f"  {a.severity:<8} {a.id}{cve}: {a.summary}" + (f"  -> fixed in {fix}" if fix else ""))
    return "\n".join(lines) + "\n"
