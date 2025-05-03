import requests

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

            # From headers (Authorization)
            auth_header = response.request.headers.get("Authorization")
            if auth_header and ("Bearer" in auth_header or "JWT" in auth_header):
                tokens.append(auth_header)

            # From cookies
            for name, value in self.session.cookies.items():
                if any(kw in name.lower() for kw in ["token", "auth", "jwt"]):
                    tokens.append(f"{name}={value}")

            self.token_data[url] = tokens

            return True

        except Exception as e:
            print(f"[!] Failed to analyze {url}: {e}")
            return False

    def report(self):
        return {
            "headers": self.header_data,
            "cookies": self.cookie_data,
            "tokens": self.token_data
        }
