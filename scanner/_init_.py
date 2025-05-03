# scanner/__init__.py

# You can optionally expose key functions here
from fuzz_engine import fuzz_payloads
from vuln_mapper import map_vulnerabilities
from header_mapper import  HeaderCookieTokenMapper
from misconfig_detector import MisconfigDetector
from ssrf_detector import scan_internal_ports,run_ssrf_module,check_ssrf_vulnerability
from token_handler import TokenExtractor

__all__ = ["fuzz_payloads", "map_vulnerabilities",
           "HeaderCookieTokenMapper","MisconfigDetector",
          "scan_internal_ports","run_ssrf_module","check_ssrf_vulnerability",
           "TokenExtractor" ]
