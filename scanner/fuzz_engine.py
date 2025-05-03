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
    "ora-00933",
    "pg_query"
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

def detect_waf(url, session):
    test_payload = "' OR '1'='1"
    try:
        resp = session.get(url, params={"q": test_payload}, timeout=5) if session else requests.get(url, params={"q": test_payload}, timeout=5)
        waf_signatures = [
            ("Cloudflare", "cf-ray"),
            ("Sucuri", "sucuri-cloudproxy"),
            ("AWS", "aws-alb"),
            ("Akamai", "akamai"),
            ("F5", "big-ip"),
            ("ModSecurity", "mod_security")
        ]
        for name, sig in waf_signatures:
            if sig.lower() in resp.headers.get("Server", "").lower() or sig.lower() in resp.text.lower():
                print(f"[!] WAF Detected: {name}")
                return name
    except Exception as e:
        print(f"[!] WAF Detection Error: {e}")
    return None

def evade_payload(payload, waf_name):
    if waf_name:
        return payload.replace("<", "<<").replace("script", "scr<script>ipt")
    return payload

def fuzz_payloads(endpoints, vuln_type, session=None):
    print(f"\n[+] Fuzzing endpoints for {vuln_type.upper()}...")

    payloads = load_payloads(vuln_type)
    headers = load_headers()
    results = []

    if not payloads:
        return results

    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        waf_name = detect_waf(endpoint, session)

        for payload in payloads:
            evaded_payload = evade_payload(payload, waf_name)
            test_url = urljoin(base, path + f"?input={evaded_payload}")
            try:
                r = session.get(test_url, headers=headers) if session else requests.get(test_url, headers=headers)
                content = r.text.lower()

                if vuln_type == "xss" and payload.lower() in content:
                    print(f"[XSS VULNERABLE] {test_url} reflected payload: {payload}")
                    results.append({"url": test_url, "payload": payload, "type": "xss", "evaded": bool(waf_name)})

                elif vuln_type == "sqli":
                    for error in SQLI_ERRORS:
                        if error in content:
                            print(f"[SQLi VULNERABLE] {test_url} triggered DB error with payload: {payload}")
                            results.append({"url": test_url, "payload": payload, "type": "sqli", "evaded": bool(waf_name)})
                            break

                elif vuln_type == "lfi" and "root:x:" in content:
                    print(f"[LFI VULNERABLE] {test_url} revealed /etc/passwd content with payload: {payload}")
                    results.append({"url": test_url, "payload": payload, "type": "lfi", "evaded": bool(waf_name)})

                elif vuln_type == "ssti" and any(i in content for i in ["49", "343", "hello world"]):
                    print(f"[SSTI VULNERABLE] {test_url} rendered payload: {payload}")
                    results.append({"url": test_url, "payload": payload, "type": "ssti", "evaded": bool(waf_name)})

            except requests.RequestException as e:
                print(f"[!] Error requesting {test_url} - {e}")

    return results
