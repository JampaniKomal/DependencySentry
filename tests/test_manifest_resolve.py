"""Manifest parsing and dependency resolution."""

import pytest
from conftest import FakeSession, release_files

from dependency_sentry.core import manifest
from dependency_sentry.core.clients import PyPI
from dependency_sentry.core.resolve import ResolutionError, from_pip_report, resolve_approximately, resolve_with_pip


def test_requirements_file_features(tmp_path):
    (tmp_path / "base.txt").write_text("requests>=2.31  # http\n")
    (tmp_path / "requirements.txt").write_text(
        "# app\n"
        "-r base.txt\n"
        "--index-url https://example.invalid/simple\n"
        "-c constraints.txt\n"
        "django==3.2.4 \\\n"
        "    --hash=sha256:abc123\n"
        'pywin32>=300; sys_platform == "win32"\n'
        "uvicorn[standard]~=0.30\n"
        "-e ./local-package\n"
        "mylib @ https://example.invalid/mylib-1.0.tar.gz\n"
        "not a requirement!!\n"
    )
    m = manifest.load(tmp_path / "requirements.txt")
    assert [str(r) for r in m.requirements] == [
        "requests>=2.31",
        "django==3.2.4",
        'pywin32>=300; sys_platform == "win32"',
        "uvicorn[standard]~=0.30",
    ]
    reasons = " | ".join(reason for _, reason in m.skipped)
    assert "editable" in reasons and "URL" in reasons and "not a valid requirement" in reasons


def test_pyproject_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["flask>=3", "jinja2==3.1.2"]\n')
    assert [r.name for r in manifest.load(tmp_path / "pyproject.toml").requirements] == ["flask", "jinja2"]


def test_pip_report_becomes_an_exact_graph(tmp_path, pip_report):
    (tmp_path / "r.txt").write_text("django==3.2.4\nrequests==2.32.3\n")
    g = from_pip_report(pip_report, manifest.load(tmp_path / "r.txt"))
    assert g.mode == "exact (pip)"
    assert {p.name for p in g.roots()} == {"Django", "requests"}
    assert g.packages["django"].version == "3.2.4"
    assert sorted(g.packages["django"].requires) == ["asgiref", "pytz", "sqlparse"]
    assert sorted(g.packages["requests"].requires) == ["certifi", "charset-normalizer", "idna", "urllib3"]
    assert g.packages["asgiref"].requires == []  # typing_extensions only below Python 3.11
    assert g.packages["urllib3"].purl.startswith("pkg:pypi/urllib3@")


def test_pip_failures_are_reported_not_hidden(tmp_path):
    (tmp_path / "r.txt").write_text("requests\n")
    with pytest.raises(ResolutionError):
        resolve_with_pip(manifest.load(tmp_path / "r.txt"), python=str(tmp_path / "no-python-here"))


def _pypi():
    base = "https://pypi.org/pypi"
    projects = {
        "app": (
            release_files("1.0", "2.0", "3.0b1", "2.5", yanked=("2.5",)),
            {"2.0": ["lib>=1.1", 'winonly; sys_platform == "win32"', "extra-dep; extra == 'fancy'"]},
        ),
        "lib": (release_files("1.0", "1.1", "1.2"), {"1.1": [], "1.2": ["leaf"]}),
        "leaf": (release_files("0.1"), {"0.1": []}),
    }
    routes = {}
    for name, (releases, requires) in projects.items():
        routes[f"{base}/{name}/json"] = {"info": {"name": name, "version": max(releases)}, "releases": releases}
        for version, deps in requires.items():
            routes[f"{base}/{name}/{version}/json"] = {"info": {"name": name, "requires_dist": deps}}
    return PyPI(FakeSession(get=routes))


def test_approximate_resolution_uses_versions_that_satisfy_the_specifiers(tmp_path):
    (tmp_path / "r.txt").write_text("app<3\nlib==1.1\nmissing-pkg\n")
    g = resolve_approximately(manifest.load(tmp_path / "r.txt"), _pypi())
    assert g.mode == "approximate"
    # 3.0b1 is a pre-release and 2.5 is yanked, so app<3 resolves to 2.0
    assert g.packages["app"].version == "2.0" and g.packages["lib"].version == "1.1"
    assert g.packages["app"].requires == ["lib"]  # the win32-only and extra-only deps do not apply
    assert "winonly" not in g.packages and "leaf" not in g.packages  # lib 1.1 has no dependencies
    assert any("missing-pkg" in w for w in g.warnings)
