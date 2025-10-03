import requests
import json
import os

class SessionHandler:
    def __init__(self):
        self.session = requests.Session()
        self.auth_headers = {}

    def set_cookie_auth(self, cookie_source):
        """Load cookies from a JSON file or parse an inline cookie header string.

        Accepts either:
          - Path to JSON file: {"sessionid": "abc", "token":"xyz"}
          - Inline cookie string: "sessionid=abc; token=xyz"
        """
        if not cookie_source:
            return
        # File path case
        if os.path.isfile(cookie_source):
            print("[+] Loading cookies from file")
            try:
                with open(cookie_source, 'r') as f:
                    cookies = json.load(f)
                if isinstance(cookies, dict):
                    self.session.cookies.update(cookies)
                    print(f"[+] Loaded cookies: {list(cookies.keys())}")
                else:
                    raise ValueError("Cookies file must contain a JSON object (dict)")
            except Exception as e:
                print(f"[!] Failed to load cookies: {e}")
            return

        # Inline cookie string fallback
        print("[+] Parsing inline cookie string")
        pairs = [p.strip() for p in cookie_source.split(';') if '=' in p]
        cookie_dict = {}
        for pair in pairs:
            name, val = pair.split('=', 1)
            cookie_dict[name.strip()] = val.strip()
        if cookie_dict:
            self.session.cookies.update(cookie_dict)
            print(f"[+] Loaded cookies: {list(cookie_dict.keys())}")
        else:
            print("[!] No valid cookie pairs found in inline string")

    def set_header_auth(self, token, header_name="Authorization"):
        """Set Bearer token (JWT) auth, avoid duplicate 'Bearer ' prefix."""
        if not token:
            return
        token = token.strip()
        if token.lower().startswith("bearer "):
            value = token  # Already has prefix
        else:
            value = f"Bearer {token}"
        print(f"[+] Setting auth header '{header_name}'")
        self.auth_headers[header_name] = value

    def set_custom_headers(self, headers_dict):
        """Set additional custom headers"""
        print(f"[+] Setting custom headers: {list(headers_dict.keys())}")
        self.auth_headers.update(headers_dict)

    def get(self, url, headers=None, **kwargs):
        """Authenticated GET request"""
        merged_headers = self.auth_headers.copy()
        if headers:
            merged_headers.update(headers)
        return self.session.get(url, headers=merged_headers, **kwargs)

    def post(self, url, data=None, json=None, headers=None, **kwargs):
        """Authenticated POST request"""
        merged_headers = self.auth_headers.copy()
        if headers:
            merged_headers.update(headers)
        return self.session.post(url, data=data, json=json, headers=merged_headers, **kwargs)

    def simulate_login(self, login_url, creds):
        """
        Perform login and store session cookies.
        creds = { "username": "admin", "password": "pass123" }
        """
        print(f"[+] Simulating login at: {login_url}")
        try:
            res = self.session.post(login_url, data=creds)
            if res.status_code == 200 and "Set-Cookie" in res.headers:
                print("[+] Login successful, cookies saved.")
            else:
                print(f"[!] Login failed, status: {res.status_code}")
        except Exception as e:
            print(f"[!] Login error: {e}")

    @property
    def cookies(self):
      return self.session.cookies

 

# Test mode
if __name__ == "__main__":
    sh = SessionHandler()
    sh.set_custom_headers({"User-Agent": "VulnEagle-Test"})
    resp = sh.get("https://httpbin.org/headers")
    print(resp.text)
