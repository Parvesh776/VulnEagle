# scanner/__init__.py

# You can optionally expose key functions here
from fuzz_engine import send_fuzz_request
from vuln_mapper import map_vulnerabilities

__all__ = ["send_fuzz_request", "map_vulnerabilities"]
