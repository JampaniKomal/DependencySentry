import json
import os
import re

from PyQt6.QtCore import QThread, pyqtSignal

from src.core.parser import ManifestParser
from src.core.resolver import DependencyResolver
from src.core.scanner import VulnerabilityScanner

_PINNED_VERSION_RE = re.compile(r'^==\s*([\w.\-+]+)$')

def _default_config():
    return {"scanner_settings": {"max_depth": 4}}

def _load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _default_config()

class AuditWorker(QThread):
    """
    Runs the full parse -> resolve -> scan pipeline off the GUI thread so the
    window doesn't freeze while making PyPI/OSV network calls.
    """
    log = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)

    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.parser = ManifestParser()
        self.resolver = DependencyResolver()
        self.scanner = VulnerabilityScanner()

    def run(self):
        try:
            self._run()
        except Exception as e:
            self.log.emit(f"[!] Critical error during audit: {e}")
            self.scan_complete.emit({"scanned": 0, "vulnerable": []})

    def _run(self):
        config = _load_config()
        max_depth = config.get("scanner_settings", {}).get("max_depth", 4)

        direct_deps = self.parser.parse(self.file_path)
        if not direct_deps:
            self.log.emit("[!] No valid packages found or file is empty.")
            self.scan_complete.emit({"scanned": 0, "vulnerable": []})
            return

        self.log.emit(f"[*] Found {len(direct_deps)} direct dependencies.")

        # Breadth-first resolution of the full dependency tree, up to max_depth.
        all_packages = {}  # name -> specifier (first one seen)
        queue = [(dep["name"], dep["specifier"], 0) for dep in direct_deps]

        while queue:
            name, specifier, depth = queue.pop(0)
            key = name.lower()
            if key in all_packages:
                continue
            all_packages[key] = (name, specifier)

            if depth < max_depth:
                for dep in self.resolver.get_dependencies(name):
                    if dep["name"].lower() not in all_packages:
                        queue.append((dep["name"], dep["specifier"], depth + 1))

        self.log.emit(f"[*] Resolved {len(all_packages)} total packages (depth <= {max_depth}).")
        self.log.emit("[*] Scanning for known vulnerabilities via OSV.dev...")

        vulnerable = []
        for name, specifier in all_packages.values():
            version = self._resolve_version(name, specifier)
            if not version:
                self.log.emit(f"[?] {name}: could not determine a version to scan, skipped.")
                continue

            vulns = self.scanner.check_package(name, version)
            if vulns:
                ids = ", ".join(v.get("id", "?") for v in vulns[:5])
                self.log.emit(f"[VULN] {name}=={version} — {len(vulns)} known vulnerabilities ({ids})")
                vulnerable.append({"name": name, "version": version, "vulns": vulns})
            else:
                self.log.emit(f"[OK]   {name}=={version} — no known vulnerabilities")

        self.log.emit(f"[*] Audit complete: {len(vulnerable)} of {len(all_packages)} packages have known vulnerabilities.")
        self.scan_complete.emit({"scanned": len(all_packages), "vulnerable": vulnerable})

    def _resolve_version(self, name, specifier):
        if specifier and specifier != "Any":
            match = _PINNED_VERSION_RE.match(specifier.strip())
            if match:
                return match.group(1)
        return self.resolver.get_latest_version(name)
