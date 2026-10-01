"""PyPI and OSV.dev clients, with caching and batching.

OSV is queried with /v1/querybatch (up to 1,000 packages per request), which
returns advisory IDs only; each distinct advisory is then fetched once from
/v1/vulns/{id} for its summary, aliases, severity and fixed versions.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

USER_AGENT = "dependency-sentry (+https://github.com/JampaniKomal/DependencySentry)"
SEVERITY_ORDER = ["UNKNOWN", "LOW", "MODERATE", "HIGH", "CRITICAL"]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


class PyPI:
    def __init__(self, session: requests.Session | None = None, base: str = "https://pypi.org/pypi"):
        self.session = session or _session()
        self.base = base.rstrip("/")
        self._cache: dict[str, dict | None] = {}

    def _get(self, path: str) -> dict | None:
        if path not in self._cache:
            try:
                r = self.session.get(f"{self.base}/{path}/json", timeout=20)
                self._cache[path] = r.json() if r.status_code == 200 else None
            except (requests.RequestException, ValueError):
                self._cache[path] = None
        return self._cache[path]

    def project(self, name: str) -> dict | None:
        return self._get(canonicalize_name(name))

    def release(self, name: str, version: str) -> dict | None:
        return self._get(f"{canonicalize_name(name)}/{version}")

    def last_release(self, name: str) -> datetime | None:
        """When the newest non-yanked file of the project was uploaded."""
        data = self.project(name)
        newest = None
        for files in (data or {}).get("releases", {}).values():
            for f in files:
                if f.get("yanked") or not f.get("upload_time_iso_8601"):
                    continue
                t = datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                newest = t if newest is None or t > newest else newest
        return newest


@dataclass
class Advisory:
    id: str
    summary: str
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    fixed: list[str] = field(default_factory=list)  # versions that fix it, for this package
    published: str = ""

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"

    @property
    def cves(self) -> list[str]:
        return sorted(a for a in [self.id, *self.aliases] if a.startswith("CVE-"))

    def fixed_after(self, version: str) -> str | None:
        """The lowest fixed version above the installed one."""
        try:
            current = Version(version)
        except InvalidVersion:
            return None
        later = []
        for text in self.fixed:
            try:
                v = Version(text)
            except InvalidVersion:  # never let one odd entry hide the others
                continue
            if v > current:
                later.append(v)
        return str(min(later)) if later else None


def _severity(vuln: dict) -> str:
    level = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if level == "MEDIUM":
        level = "MODERATE"
    return level if level in SEVERITY_ORDER else "UNKNOWN"


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    fixed = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or canonicalize_name(pkg.get("name", "")) != package:
            continue
        for r in affected.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges give commit hashes, not versions
            fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return sorted(set(fixed))


class OSV:
    def __init__(self, session: requests.Session | None = None, base: str = "https://api.osv.dev/v1"):
        self.session = session or _session()
        self.base = base.rstrip("/")
        self._vulns: dict[str, dict] = {}

    def query(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
        """{(canonical name, version): [advisory ids]} for every package."""
        result: dict[tuple[str, str], list[str]] = {}
        for start in range(0, len(packages), 1000):
            chunk = packages[start : start + 1000]
            body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]}
            r = self.session.post(f"{self.base}/querybatch", json=body, timeout=60)
            r.raise_for_status()
            for (name, version), res in zip(chunk, r.json().get("results", []), strict=False):
                ids = [v["id"] for v in res.get("vulns", [])]
                # very affected packages are paginated
                token = res.get("next_page_token")
                while token:
                    q = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version, "page_token": token}
                    page = self.session.post(f"{self.base}/query", json=q, timeout=60).json()
                    ids += [v["id"] for v in page.get("vulns", [])]
                    token = page.get("next_page_token")
                result[(canonicalize_name(name), version)] = ids
        return result

    def vuln(self, vuln_id: str) -> dict:
        if vuln_id not in self._vulns:
            r = self.session.get(f"{self.base}/vulns/{vuln_id}", timeout=30)
            r.raise_for_status()
            self._vulns[vuln_id] = r.json()
        return self._vulns[vuln_id]

    def advisories(self, package: str, ids: list[str], workers: int = 8) -> list[Advisory]:
        """Details for one package's advisories, merging IDs that alias each other (PYSEC and GHSA)."""
        with ThreadPoolExecutor(workers) as pool:
            vulns = dict(zip(ids, pool.map(self.vuln, ids), strict=True))
        merged: list[Advisory] = []
        seen: set[str] = set()
        # prefer GHSA records: they carry a severity
        for vid in sorted(ids, key=lambda i: (not i.startswith("GHSA"), i)):
            if vid in seen:
                continue
            v = vulns[vid]
            group = {vid, *v.get("aliases", [])} & set(ids)
            seen |= group
            others = [vulns[g] for g in group if g != vid]
            severity = max([_severity(v), *map(_severity, others)], key=SEVERITY_ORDER.index)
            aliases = sorted({a for x in [v, *others] for a in [x["id"], *x.get("aliases", [])]} - {vid})
            fixed = sorted({f for x in [v, *others] for f in _fixed_versions(x, package)})
            merged.append(
                Advisory(
                    id=vid,
                    summary=v.get("summary") or (v.get("details") or "").split("\n")[0][:200],
                    aliases=aliases,
                    severity=severity,
                    fixed=fixed,
                    published=v.get("published", ""),
                )
            )
        return sorted(merged, key=lambda a: (-SEVERITY_ORDER.index(a.severity), a.id))


def now() -> datetime:
    return datetime.now(timezone.utc)
