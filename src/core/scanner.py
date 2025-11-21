import requests
import json

class VulnerabilityScanner:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"
        self.session = requests.Session()

    def check_package(self, package_name, version):
        """
        Queries the OSV.dev API for known vulnerabilities for a specific package version.
        Returns a list of vulnerability objects (dictionaries) or an empty list if safe.
        """
        # Construct the standard OSV query payload
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI"
            },
            "version": version
        }
        
        try:
            # We use POST because the query is a JSON object
            response = self.session.post(self.api_url, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            # The API returns a "vulns" list if threats are found
            return data.get("vulns", [])
            
        except Exception as e:
            print(f"[!] OSV API Error for {package_name}@{version}: {e}")
            return []

# --- Manual Test Block ---
if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    
    # Test Case: Django 3.2.4 (Known to be vulnerable)
    test_pkg = "django"
    test_ver = "3.2.4"
    
    print(f"--- Testing Vulnerability Scanner ---")
    print(f"[*] Querying OSV database for: {test_pkg} == {test_ver}...")
    
    vulns = scanner.check_package(test_pkg, test_ver)
    
    if vulns:
        print(f"\n[!] CRITICAL: Found {len(vulns)} known vulnerabilities!")
        # Print details of the first one found
        v = vulns[0]
        print(f"    ID: {v.get('id')}")
        print(f"    Summary: {v.get('summary', 'No summary provided')}")
        print(f"    Details: {v.get('details', 'No details')[:100]}...") # Truncated
    else:
        print(f"\n[+] Safe: No vulnerabilities found for {test_pkg} {test_ver}.")