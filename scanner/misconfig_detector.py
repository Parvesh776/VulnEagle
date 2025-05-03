import requests
from urllib.parse import urlparse, urljoin

class MisconfigDetector:
    def __init__(self):
        self.results = []

    def check_cors(self, url):
        try:
            headers = {
                "Origin": "https://evil.com"
            }
            r = requests.get(url, headers=headers)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if "evil.com" in acao or "*" in acao:
                self.results.append(f"[CORS] Potentially misconfigured CORS: {acao}")
        except Exception as e:
            self.results.append(f"[CORS] Error checking CORS: {str(e)}")

    def detect_open_redirects(self, url):
        redirect_params = ["redirect", "url", "next", "dest", "continue", "return"]
        evil_url = "https://attacker.com"

        for param in redirect_params:
            test_url = f"{url}?{param}={evil_url}"
            try:
                resp = requests.get(test_url, allow_redirects=False)
                if resp.status_code in [301, 302, 303] and "attacker.com" in resp.headers.get("Location", ""):
                    self.results.append(f"[OPEN REDIRECT] Vulnerable param: {param} in {test_url}")
            except Exception as e:
                self.results.append(f"[OPEN REDIRECT] Error with {test_url}: {str(e)}")

    def detect_exposed_apis(self, url):
        api_paths = ["/api/", "/api/v1/", "/swagger", "/openapi.json", "/.env", "/config", "/debug"]
        for path in api_paths:
            test_url = urljoin(url, path)
            try:
                resp = requests.get(test_url)
                if resp.status_code == 200 and any(x in resp.text.lower() for x in ["swagger", "openapi", "api", "token", "config"]):
                    self.results.append(f"[EXPOSED API] {test_url} returned suspicious content.")
            except Exception as e:
                self.results.append(f"[EXPOSED API] Error accessing {test_url}: {str(e)}")

    def run_all_checks(self, target_url):
        print(f"[*] Running misconfiguration checks on: {target_url}")
        self.check_cors(target_url)
        self.detect_open_redirects(target_url)
        self.detect_exposed_apis(target_url)
        return self.results


if __name__ == "__main__":
    detector = MisconfigDetector()
    target_url = "https://example.com"  # Replace with actual URL
    results = detector.run_all_checks(target_url)
    for line in results:
        print(line)
