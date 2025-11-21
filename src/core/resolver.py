import requests
import sys
from packaging.requirements import Requirement

class DependencyResolver:
    def __init__(self):
        self.base_url = "https://pypi.org/pypi"
        self.session = requests.Session()
        # Simple in-memory cache to prevent redundant API calls
        self.cache = {}

    def get_dependencies(self, package_name):
        """
        Fetches direct dependencies for a given package from PyPI.
        Returns a list of dictionary objects: {'name': str, 'version_spec': str}
        """
        package_name = package_name.lower()
        
        if package_name in self.cache:
            return self.cache[package_name]

        print(f"[*] Fetching metadata for: {package_name}...")
        
        url = f"{self.base_url}/{package_name}/json"
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                print(f"[!] Package not found: {package_name}")
                return []
            
            response.raise_for_status()
            data = response.json()
            
            # "requires_dist" contains the list of dependencies
            raw_dependencies = data.get("info", {}).get("requires_dist", [])
            
            parsed_deps = []
            
            if raw_dependencies:
                for dep_str in raw_dependencies:
                    try:
                        req = Requirement(dep_str)
                        
                        # CRITICAL: Ignore "extra" dependencies (e.g. "requests[security]")
                        # We only want the core mandatory dependencies for now.
                        if req.marker:
                            # Evaluate marker with empty environment to see if it applies strictly
                            # This is a simplification; mostly we just skip markers for this MVP
                            continue
                            
                        parsed_deps.append({
                            "name": req.name,
                            "specifier": str(req.specifier) if req.specifier else "Any"
                        })
                    except Exception as e:
                        print(f"[!] Error parsing dependency '{dep_str}': {e}")

            self.cache[package_name] = parsed_deps
            return parsed_deps

        except Exception as e:
            print(f"[!] Network error fetching {package_name}: {e}")
            return []

# --- Manual Test Block ---
if __name__ == "__main__":
    # This allows us to test this specific file in isolation
    resolver = DependencyResolver()
    target = "requests"
    print(f"--- Testing Resolver on '{target}' ---")
    deps = resolver.get_dependencies(target)
    
    print(f"\nResults for {target}:")
    for d in deps:
        print(f"  -> {d['name']} ({d['specifier']})")