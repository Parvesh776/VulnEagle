import requests

class SessionHandler:
    def __init__(self):
        self.session = requests.Session()
        self.auth_headers = {}

    def set_cookie_auth(self, cookies):
        """Manually set auth cookies"""
        print("[+] Setting cookie-based auth")
        if isinstance(cookies, dict):
            self.session.cookies.update(cookies)
        else:
            raise ValueError("Cookies should be a dictionary")

    def set_jwt_auth(self, token, header_name="Authorization"):
        """Set JWT auth token"""
        print("[+] Setting JWT-based auth")
        self.auth_headers[header_name] = f"Bearer {token}"

    def get(self, url, **kwargs):
        """Authenticated GET request"""
        return self.session.get(url, headers=self.auth_headers, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """Authenticated POST request"""
        return self.session.post(url, data=data, json=json, headers=self.auth_headers, **kwargs)

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
if __name__ == "__main__":
    sh = SessionHandler()

    # Example 1: JWT Token
    # sh.set_jwt_auth("eyJh...abc")

    # Example 2: Cookie-based Auth
    # sh.set_cookie_auth({"sessionid": "xyz123"})

    # Example 3: Simulate Login
    # sh.simulate_login("https://site.com/login", {"username": "admin", "password": "pass123"})

    # Test request
    resp = sh.get("https://httpbin.org/cookies")
    print(resp.text)

import json

def load_cookies_from_file(file_path):
    """
    Load cookies from a JSON file and return as a dictionary.
    File format: { "sessionid": "xyz123", "csrftoken": "abc456" }
    """
    try:
        with open(file_path, 'r') as f:
            cookies = json.load(f)
            print(f"[+] Loaded cookies from {file_path}")
            return cookies
    except Exception as e:
        print(f"[!] Failed to load cookies: {e}")
        return {}
