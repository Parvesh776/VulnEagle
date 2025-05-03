import os
import json
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

def load_headers():
    header_path = os.path.join(os.path.dirname(__file__), '..', 'headers.json')
    try:
        with open(header_path, 'r') as f:
            headers = json.load(f)
            print("[+] Loaded custom headers for auth/session.")
            return headers
    except FileNotFoundError:
        print("[!] headers.json not found. Proceeding without custom headers.")
        return {}
    except json.JSONDecodeError:
        print("[!] Invalid JSON format in headers.json.")
        return {}

def fuzz_payloads(endpoints, vuln_type, session=None):
    print(f"\n[+] Fuzzing endpoints for {vuln_type.upper()}...")

    payloads = load_payloads(vuln_type)
    headers = load_headers()

    if not payloads:
        return

    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path

        for payload in payloads:
            test_url = urljoin(base, path + f"?input={payload}")
            try:
                if session:
                    r = session.get(test_url, headers=headers)
                else:
                    r = requests.get(test_url, headers=headers)

                content = r.text.lower()

                if vuln_type == "xss" and payload in content:
                    print(f"[XSS VULNERABLE] {test_url} reflected payload: {payload}")

                elif vuln_type == "sqli":
                    for error in SQLI_ERRORS:
                        if error in content:
                            print(f"[SQLi VULNERABLE] {test_url} triggered DB error with payload: {payload}")
                            break

                elif vuln_type == "lfi" and "root:x:" in content:
                    print(f"[LFI VULNERABLE] {test_url} revealed /etc/passwd content with payload: {payload}")

                elif vuln_type == "ssti" and any(indicator in content for indicator in ["49", "343", "hello world"]):
                    print(f"[SSTI VULNERABLE] {test_url} rendered payload: {payload}")

            except requests.RequestException as e:
                print(f"[!] Error requesting {test_url} - {e}")
