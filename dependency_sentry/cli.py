"""dependency-sentry: audit a Python manifest from the command line.

    dependency-sentry requirements.txt
    dependency-sentry pyproject.toml --sbom sbom.cdx.json --fail-on high

Exit code: 0 if nothing at or above --fail-on was found, 1 if something was,
2 if the manifest could not be read.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import audit, export
from .core.clients import SEVERITY_ORDER

LEVELS = {"none": None, "any": "UNKNOWN", "low": "LOW", "moderate": "MODERATE", "high": "HIGH", "critical": "CRITICAL"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dependency-sentry", description=__doc__.split("\n")[0])
    parser.add_argument("manifest", help="requirements.txt (or any requirements file) or pyproject.toml")
    parser.add_argument("--approximate", action="store_true", help="skip pip's resolver; walk PyPI metadata instead")
    parser.add_argument("--abandoned-after", type=int, default=730, metavar="DAYS", help="0 turns the check off")
    parser.add_argument("--sbom", metavar="FILE", help="write a CycloneDX 1.6 JSON SBOM")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--fail-on", choices=list(LEVELS), default="any", help="lowest severity that fails (exit 1)")
    parser.add_argument("--quiet", "-q", action="store_true", help="no progress messages")
    parser.add_argument("--version", action="version", version=f"dependency-sentry {__version__}")
    args = parser.parse_args(argv)

    settings = audit.Settings(
        mode="approximate" if args.approximate else "exact", abandoned_after_days=args.abandoned_after
    )
    log = (lambda _m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    try:
        report = audit.run(args.manifest, settings, log)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"dependency-sentry: cannot read {args.manifest}: {exc}", file=sys.stderr)
        return 2

    if args.sbom:
        with open(args.sbom, "w", encoding="utf-8") as f:
            json.dump(export.cyclonedx(report), f, indent=2)
    if args.json:
        json.dump(export.to_json(report), sys.stdout, indent=2)
        print()
    else:
        sys.stdout.write(export.to_text(report))

    level = LEVELS[args.fail_on]
    if level is None:
        return 0
    return 1 if report.count_at_least(level) and level in SEVERITY_ORDER else 0


if __name__ == "__main__":
    sys.exit(main())
