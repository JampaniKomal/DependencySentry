import os
from packaging.requirements import Requirement

class ManifestParser:
    def parse(self, file_path):
        """
        Reads a requirements.txt file and returns a list of package names.
        """
        if not os.path.exists(file_path):
            return []

        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse the line using packaging.requirements
                    try:
                        req = Requirement(line)
                        dependencies.append(req.name)
                    except Exception:
                        # Skip lines we can't parse (like --extra-index-url)
                        continue
                        
            return list(set(dependencies)) # Remove duplicates
            
        except Exception as e:
            print(f"[!] Error parsing file: {e}")
            return []