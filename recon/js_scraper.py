import re
import requests 
import requests
from urllib.parse import urljoin, urlparse

def extract_js_urls_from_html(url):
    """Fetch JS file URLs from HTML page."""
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
    except Exception as e:
        print(f"[!] Error fetching page: {e}")
        return []

    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', res.text)
    return [urljoin(url, js_url) for js_url in js_urls]

def extract_endpoints_from_js(js_code):
    """Extract API endpoints from JS code using regex."""
    regex = re.compile(r'["\']((?:\/|https?:\/\/)[\w\-\/\.\?\=\&]+)["\']')
    return list(set(regex.findall(js_code)))

def scrape_js_endpoints(target_url):
    js_files = extract_js_urls_from_html(target_url)
    all_endpoints = set()

    for js_url in js_files:
        print(f"[+] Fetching JS: {js_url}")
        try:
            js_content = requests.get(js_url, timeout=10).text
            endpoints = extract_endpoints_from_js(js_content)
            print(f"  ↳ Found {len(endpoints)} endpoints")
            all_endpoints.update(endpoints)
        except Exception as e:
            print(f"  [!] Failed to fetch {js_url}: {e}")

    return list(all_endpoints)

def main(url):
    return scrape_js_endpoints(url)

if __name__ == "__main__":
    url = input("Enter target URL (e.g. https://site.com): ").strip()
    endpoints = main(url)
    print("\n Endpoints Found:")
    for ep in endpoints:
        print(" -", ep)

from urllib.parse import urljoin, urlparse

def extract_js_urls_from_html(url):
    """Fetch JS file URLs from HTML page"""
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
    except Exception as e:
        print(f"[!] Error fetching page: {e}")
        return []

    js_urls = re.findall(r'<script[^>]+src="([^"]+)"', res.text)
    full_urls = [urljoin(url, js_url) for js_url in js_urls]
    return full_urls

def extract_endpoints_from_js(js_code):
    """Extract API endpoints from JS code using regex"""
    regex = re.compile(r'["\']((?:\/|https?:\/\/)[\w\-\/\.\?\=\&]+)["\']')
    return list(set(match.group(1) for match in regex.finditer(js_code)))

def scrape_js_endpoints(target_url):
    js_files = extract_js_urls_from_html(target_url)
    all_endpoints = set()

    for js_url in js_files:
        print(f"[+] Fetching JS: {js_url}")
        try:
            js_content = requests.get(js_url, timeout=10).text
            endpoints = extract_endpoints_from_js(js_content)
            print(f"  ↳ Found {len(endpoints)} endpoints")
            all_endpoints.update(endpoints)
        except Exception as e:
            print(f"  [!] Failed to fetch {js_url}: {e}")
            continue

    return list(all_endpoints)

if __name__ == "__main__":
    url = input("Enter target URL (e.g. https://site.com): ").strip()
    endpoints = scrape_js_endpoints(url)
    print("\n📍 Endpoints Found:")
    for ep in endpoints:
        print(" -", ep)

def main(url):
    return scrape_js_endpoints(url)
if __name__ == "__main__":
    url = input("Enter target URL (e.g. https://site.com): ").strip()
    endpoints = scrape_js_endpoints(url)
    print("\n📍 Endpoints Found:")
    for ep in endpoints:
        print(" -", ep)