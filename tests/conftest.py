"""Fakes for PyPI and OSV.dev, so the tests run offline and deterministically."""

import json
from pathlib import Path

import pytest

from dependency_sentry.core import audit
from dependency_sentry.core.clients import OSV, PyPI
from dependency_sentry.core.resolve import from_pip_report

FIXTURES = Path(__file__).parent / "fixtures"


class Response:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Routes GET/POST by URL; records calls."""

    def __init__(self, get=None, post=None):
        self.get_routes = get or {}
        self.post_handler = post
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        if url in self.get_routes:
            return Response(200, self.get_routes[url])
        return Response(404, None)

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url, json))
        return Response(200, self.post_handler(url, json))


def release_files(*versions, yanked=(), date="2024-01-01T00:00:00Z"):
    return {v: [{"upload_time_iso_8601": date, "yanked": v in yanked}] for v in versions}


def advisory(vid, package, fixed, severity=None, aliases=(), summary="A bug"):
    data = {
        "id": vid,
        "summary": summary,
        "aliases": list(aliases),
        "published": "2023-05-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}] + [{"fixed": f} for f in fixed]}],
            }
        ],
    }
    if severity:
        data["database_specific"] = {"severity": severity}
    return data


@pytest.fixture
def pip_report():
    return json.loads((FIXTURES / "pip-report.json").read_text())


OSV_BASE = "https://api.osv.dev/v1"
VULNS = {
    "PYSEC-2021-1": advisory("PYSEC-2021-1", "django", ["3.2.5"], aliases=["GHSA-aaaa", "CVE-2021-1111"]),
    "GHSA-aaaa": advisory("GHSA-aaaa", "django", ["3.2.5"], "HIGH", ["PYSEC-2021-1", "CVE-2021-1111"], "SQL injection"),
    "GHSA-bbbb": advisory("GHSA-bbbb", "django", ["3.2.13", "4.0.4"], "CRITICAL", ["CVE-2022-2222"], "Worse"),
    "GHSA-cccc": advisory("GHSA-cccc", "requests", ["2.32.4"], "MODERATE", ["CVE-2024-3333"], "Leak"),
}
AFFECTED = {"django": ["PYSEC-2021-1", "GHSA-aaaa", "GHSA-bbbb"], "requests": ["GHSA-cccc"]}


def _osv_post(url, body):
    if url.endswith("/querybatch"):
        return {
            "results": [{"vulns": [{"id": i} for i in AFFECTED.get(q["package"]["name"], [])]} for q in body["queries"]]
        }
    raise AssertionError(url)


def fake_osv():
    return OSV(FakeSession(get={f"{OSV_BASE}/vulns/{k}": v for k, v in VULNS.items()}, post=_osv_post))


def fake_pypi(old=("pytz",)):
    routes = {}
    for name in [
        "django",
        "requests",
        "asgiref",
        "certifi",
        "charset-normalizer",
        "idna",
        "sqlparse",
        "urllib3",
        "pytz",
    ]:
        date = "2019-01-01T00:00:00Z" if name in old else "2026-08-01T00:00:00Z"
        routes[f"https://pypi.org/pypi/{name}/json"] = {
            "info": {"name": name},
            "releases": release_files("1.0", date=date),
        }
    return PyPI(FakeSession(get=routes))


@pytest.fixture
def manifest_file(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("django==3.2.4\nrequests==2.32.3\n")
    return path


@pytest.fixture
def report(manifest_file, pip_report):
    return audit.run(
        str(manifest_file),
        pypi=fake_pypi(),
        osv=fake_osv(),
        pip_resolve=lambda m: from_pip_report(pip_report, m),
    )
