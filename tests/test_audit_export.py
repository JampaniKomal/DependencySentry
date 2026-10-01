"""OSV lookups, the audit, the exports and the command line."""

import json
import os

import pytest
from conftest import advisory, fake_osv, fake_pypi

from dependency_sentry import cli
from dependency_sentry.core import audit, export, manifest
from dependency_sentry.core.resolve import ResolutionError, from_pip_report


def test_osv_aliases_are_merged_and_ranked(report):
    django = report.advisories["django"]
    assert [a.id for a in django] == ["GHSA-bbbb", "GHSA-aaaa"]  # PYSEC-2021-1 is the same advisory as GHSA-aaaa
    assert django[1].aliases == ["CVE-2021-1111", "PYSEC-2021-1"] and django[1].cves == ["CVE-2021-1111"]
    assert django[0].severity == "CRITICAL" and django[0].fixed_after("3.2.4") == "3.2.13"
    assert report.worst("django") == "CRITICAL" and report.worst("urllib3") is None
    assert report.count_at_least("HIGH") == 2 and report.count_at_least("UNKNOWN") == 3


def test_stale_packages_are_flagged(report):
    assert list(report.abandoned) == ["pytz"]


def test_exact_resolution_falls_back_to_approximate(manifest_file, pip_report, monkeypatch):
    def broken(_m):
        raise ResolutionError("pip could not resolve the manifest: no matching distribution")

    called = {}

    def approx(m, pypi, depth):
        called["yes"] = True
        return from_pip_report(pip_report, m)

    monkeypatch.setattr(audit, "resolve_approximately", approx)
    r = audit.run(str(manifest_file), pypi=fake_pypi(), osv=fake_osv(), pip_resolve=broken)
    assert called and "Exact resolution failed" in r.notes[0]


def test_cyclonedx_sbom_is_valid_and_complete(report):
    bom = export.cyclonedx(report)
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert errors is None, errors
    refs = {c["bom-ref"] for c in bom["components"]}
    assert "pkg:pypi/django@3.2.4" in refs and len(refs) == len(report.graph.packages)
    root = next(d for d in bom["dependencies"] if d["ref"] == "root")
    assert set(root["dependsOn"]) == {"pkg:pypi/django@3.2.4", "pkg:pypi/requests@2.32.3"}
    vuln = next(v for v in bom["vulnerabilities"] if v["id"] == "GHSA-bbbb")
    assert (
        vuln["ratings"][0]["severity"] == "critical" and vuln["recommendation"] == "Upgrade Django to 3.2.13 or later"
    )


def test_text_and_json_reports(report):
    text = export.to_text(report)
    assert "Django==3.2.4  [2 advisories, worst CRITICAL]" in text
    assert "  sqlparse==" in text  # the tree shows transitive dependencies under their parent
    assert "fixed in 3.2.13" in text and "CVE-2022-2222" in text
    data = export.to_json(report)
    assert data["resolution"] == "exact (pip)" and data["packages"][0]["direct"]


def test_cli_exit_codes(manifest_file, report, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(audit, "run", lambda *a, **k: report)
    sbom = tmp_path / "sbom.json"
    assert cli.main([str(manifest_file), "-q", "--sbom", str(sbom)]) == 1
    assert json.loads(sbom.read_text())["bomFormat"] == "CycloneDX"
    assert cli.main([str(manifest_file), "-q", "--fail-on", "critical"]) == 1
    assert cli.main([str(manifest_file), "-q", "--fail-on", "none"]) == 0
    capsys.readouterr()
    assert cli.main([str(manifest_file), "-q", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["packages"]


def test_cli_unreadable_manifest(tmp_path):
    assert cli.main([str(tmp_path / "missing.txt"), "-q"]) == 2


@pytest.mark.network
@pytest.mark.skipif(not os.environ.get("DEPENDENCY_SENTRY_NETWORK"), reason="set DEPENDENCY_SENTRY_NETWORK=1")
def test_real_audit_of_the_example_manifest():
    """Against the live services: pip's resolver, PyPI and OSV.dev."""
    path = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable-requirements.txt")
    r = audit.run(path)
    assert r.graph.mode == "exact (pip)" and r.graph.packages["django"].version == "3.2.4"
    django = r.advisories["django"]
    assert len(django) > 10 and any(a.cves for a in django) and any(a.severity == "CRITICAL" for a in django)
    assert any(a.fixed_after("3.2.4") for a in django)
    assert manifest.load(path).requirements


def test_git_commit_fixes_do_not_hide_version_fixes():
    from dependency_sentry.core.clients import Advisory, _fixed_versions

    vuln = advisory("PYSEC-2023-192", "urllib3", ["1.26.17", "2.0.6"])
    vuln["affected"][0]["ranges"].append(
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "644124ecd0b6e417c527191f866daa05a5a2056d"}]}
    )
    assert _fixed_versions(vuln, "urllib3") == ["1.26.17", "2.0.6"]
    odd = Advisory("X", "x", fixed=["not-a-version", "1.26.17", "2.0.6"])
    assert odd.fixed_after("1.23") == "1.26.17" and odd.fixed_after("2.0.6") is None
