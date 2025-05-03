import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from auth.session_handler import SessionHandler

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy"
]

class HeaderCookieTokenMapper:
    def __init__(self, session: requests.Session):
        self.session = session
        self.header_data = {}
        self.cookie_data = {}
        self.token_data = {}

    def analyze_response(self, url):
        try:
            response = self.session.get(url, timeout=10)

            # 1. Capture headers
            self.header_data[url] = dict(response.request.headers)

            # 2. Capture cookies
            self.cookie_data[url] = self.session.cookies.get_dict()

            # 3. Capture tokens (from headers or cookies)
            tokens = []

            # From Authorization header
            auth_header = response.request.headers.get("Authorization")
            if auth_header and ("Bearer" in auth_header or "JWT" in auth_header):
                tokens.append(auth_header)

            # From cookies
            for name, value in self.session.cookies.items():
                if any(kw in name.lower() for kw in ["token", "auth", "jwt"]):
                    tokens.append(f"{name}={value}")

            self.token_data[url] = tokens

        except Exception as e:
            print(f"[!] Failed to analyze headers/cookies: {e}")

    def report(self):
        return {
            "headers": self.header_data,
            "cookies": self.cookie_data,
            "tokens": self.token_data
        }

def map_inputs(url, session: SessionHandler):
    print(f"[+] Mapping inputs for: {url}")
    try:
        res = session.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        form_inputs = []

        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    form_details["inputs"].append(name)

            form_inputs.append(form_details)

        return form_inputs

    except Exception as e:
        print(f"[!] Failed to parse inputs: {e}")
        return []

def check_misconfigurations(url):
    print(f"\n🔎 Checking misconfigurations for: {url}")
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        headers = response.headers

        # CORS Misconfig
        origin = headers.get("Access-Control-Allow-Origin", "")
        credentials = headers.get("Access-Control-Allow-Credentials", "")
        if origin == "*" and credentials.lower() == "true":
            print("[⚠️] Potential CORS Misconfiguration: ACAO=* with credentials=true")

        # Missing security headers
        for header in SECURITY_HEADERS:
            if header not in headers:
                print(f"[❌] Missing Security Header: {header}")

        # Open Redirect Test
        parsed_url = url if "?" not in url else url.split("?")[0]
        redirect_test_url = f"{parsed_url}?next=http://evil.com"
        r = requests.get(redirect_test_url, allow_redirects=False)
        location = r.headers.get("Location", "")
        if "evil.com" in location:
            print(f"[🔁] Open Redirect Vulnerability Detected: {redirect_test_url}")

    except Exception as e:
        print(f"[!] Error during misconfiguration check: {e}")

if __name__ == "__main__":
    target = "https://example.com/login"  # 👈 Replace with your actual target
    session = SessionHandler()

    print("\n📍 Discovered Forms + Inputs:")
    input_map = map_inputs(target, session)
    for form in input_map:
        print(f"\n[Form] Action: {form['action']} | Method: {form['method']}")
        print("Inputs:", ", ".join(form['inputs']))

    # Header, Cookie, Token Mapper
    mapper = HeaderCookieTokenMapper(session)
    mapper.analyze_response(target)
    mapping_report = mapper.report()

    print("\n📦 Headers:")
    for k, v in mapping_report["headers"].get(target, {}).items():
        print(f"  {k}: {v}")

    print("\n🍪 Cookies:")
    print(mapping_report["cookies"].get(target, {}))

    print("\n🔐 Tokens:")
    print(mapping_report["tokens"].get(target, []))

    # ✅ Misconfig detection
    check_misconfigurations(target)
