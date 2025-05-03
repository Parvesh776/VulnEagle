# subdomain_enum.py

import requests
import re
import json
from urllib.parse import urlparse

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def from_crtsh(self):
        print("[+] Gathering subdomains from crt.sh")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = json.loads(response.text)
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        if self.domain in sub:
                            self.subdomains.add(sub.strip())
        except Exception as e:
            print(f"[-] crt.sh error: {e}")

    def from_dnsdumpster(self):
        print("[+] Gathering subdomains from DNSdumpster")
        session = requests.Session()
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            resp = session.get("https://dnsdumpster.com", headers=headers)
            match = re.search(r'name="csrfmiddlewaretoken" value="(.*?)"', resp.text)
            if not match:
                print("[-] CSRF token not found. DNSdumpster may have blocked this request.")
                return
            csrf_token = match.group(1)
            cookies = resp.cookies.get_dict()

            post_data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain
            }
            headers['Referer'] = 'https://dnsdumpster.com'
            result = session.post("https://dnsdumpster.com", cookies=cookies, data=post_data, headers=headers)

            subdomains = re.findall(r">([a-zA-Z0-9_.-]*\." + re.escape(self.domain) + r")<", result.text)
            for sub in subdomains:
                self.subdomains.add(sub.strip())
        except Exception as e:
            print(f"[-] DNSdumpster error: {e}")

    def run_all(self):
        self.from_crtsh()
        self.from_dnsdumpster()
        return sorted(self.subdomains)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain to enumerate subdomains for")
    args = parser.parse_args()

    print(f"[*] Enumerating subdomains for: {args.domain}\n")
    enum = SubdomainEnumerator(args.domain)
    results = enum.run_all()

    print("\n[+] Subdomains Found:")
    for sub in results:
        print(f" - {sub}")

    print(f"\n[✓] Total: {len(results)} subdomains")
