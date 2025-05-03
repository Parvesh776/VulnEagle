import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import re

# --- Content type detector (you can expand this logic) ---
def detect_content_type(url):
    try:
        print("[*] Detecting content type...")
        res = requests.head(url, allow_redirects=True, timeout=10)
        content_type = res.headers.get('Content-Type', 'unknown')
        print(f"[+] Content-Type: {content_type}")
    except Exception as e:
        print(f"[!] Error detecting content type: {e}")

# --- Static crawler placeholder ---
def intelligent_crawler(url, max_depth=1):
    # This is a basic placeholder logic
    print("[*] Running static crawling...")
    visited = set()
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link['href']
            if href.startswith("http"):
                visited.add(href)
            elif href.startswith("/"):
                visited.add(url.rstrip("/") + href)
    except Exception as e:
        print(f"[!] Static crawl error: {e}")
    return visited

# --- Dynamic crawler with Playwright ---
def extract_dynamic_links(url):
    print("[*] Crawling dynamic content using Playwright...")
    visited = set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=60000)

            html = page.content()
            soup = BeautifulSoup(html, "html.parser")

            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith("http"):
                    visited.add(href)
                elif href.startswith("/"):
                    visited.add(url.rstrip("/") + href)

            browser.close()
    except Exception as e:
        print(f"[!] Dynamic crawl error: {e}")
    return visited

# --- JS Endpoint Extractor ---
def extract_js_endpoints(url):
    print("[*] Extracting JS-based endpoints...")
    endpoints = set()
    try:
        res = requests.get(url)
        scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', res.text)
        for script in scripts:
            full_url = script if script.startswith("http") else url.rstrip("/") + "/" + script.lstrip("/")
            js_res = requests.get(full_url)
            found = re.findall(r'\/[a-zA-Z0-9_/.-]*', js_res.text)
            for ep in found:
                if len(ep) > 1 and "." not in ep.split("/")[-1]:  # skip files
                    endpoints.add(ep)
    except Exception as e:
        print(f"[!] JS parse error: {e}")
    return list(endpoints)

# --- Subdomain Enumerator ---
def enum_subdomains(domain):
    print("[*] Enumerating subdomains from crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            entries = res.json()
            subdomains = set()
            for entry in entries:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    if domain in sub:
                        subdomains.add(sub.strip())
            return list(subdomains)
    except Exception as e:
        print(f"[!] Error fetching subdomains: {e}")
    return []

# --- Unified Smart Recon Function ---
def smart_recon(url):
    print(f"\n=== Smart Recon Started on: {url} ===")

    # Step 1: Detect content type
    detect_content_type(url)

    # Step 2: Subdomain Enumeration
    domain = re.sub(r"https?://", "", url).split("/")[0]
    subdomains = enum_subdomains(domain)
    print(f"\n[+] Found {len(subdomains)} Subdomains:")
    for s in subdomains:
        print(f" - {s}")

    # Step 3: Static Crawl
    static_links = intelligent_crawler(url)
    print(f"\n[+] Found {len(static_links)} Static Links:")
    for link in static_links:
        print(f" - {link}")

    # Step 4: Dynamic Crawl
    dynamic_links = extract_dynamic_links(url)
    print(f"\n[+] Found {len(dynamic_links)} Dynamic Links:")
    for link in dynamic_links:
        print(f" - {link}")

    # Step 5: Merge all URLs
    all_links = static_links.union(dynamic_links)
    print(f"\n[+] Total Unique URLs: {len(all_links)}")

    # Step 6: JS-based Endpoints
    js_endpoints = extract_js_endpoints(url)
    print(f"\n[+] Extracted {len(js_endpoints)} JS Endpoints:")
    for e in js_endpoints:
        print(f" - {e}")

    print("\n=== Smart Recon Complete ===")

    return {
        "subdomains": subdomains,
        "static_links": list(static_links),
        "dynamic_links": list(dynamic_links),
        "all_links": list(all_links),
        "js_endpoints": js_endpoints
    }
