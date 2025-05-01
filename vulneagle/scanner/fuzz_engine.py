import os
import requests
from urllib.parse import urlparse, urljoin

# SQLi specific DB error patterns
SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax error",
    "fatal error",
    "ora-00933",  # Oracle
    "pg_query"    # PostgreSQL
]

def load_payloads(vuln_type):
    payload_file = os.path.join(os.path.dirname(__file__), '..', 'payloads', f'{vuln_type}.txt')
    try:
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] No payloads found for: {vuln_type}")
        return []

def fuzz_payloads(endpoints, vuln_type, session=None):
    print(f"\n[+] Fuzzing endpoints for {vuln_type.upper()}...")

    payloads = load_payloads(vuln_type)
    if not payloads:
        return

    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path

        for payload in payloads:
            test_url = urljoin(base, path + f"?input={payload}")
            try:
                r = session.get(test_url) if session else requests.get(test_url)
                content = r.text.lower()

                if vuln_type == "xss" and payload in content:
                    print(f"[XSS VULNERABLE] {test_url} reflected payload: {payload}")

                elif vuln_type == "sqli":
                    for error in SQLI_ERRORS:
                        if error in content:
                            print(f"[SQLi VULNERABLE] {test_url} triggered DB error with payload: {payload}")
                            break

                # Future scope: add more vulnerability types here

            except requests.RequestException as e:
                print(f"[!] Error requesting {test_url} - {e}")