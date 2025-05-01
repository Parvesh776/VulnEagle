from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse
import re

def extract_dynamic_links(url):
    dynamic_links = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            print(f"[+] Crawling: {url}")
            page.goto(url, timeout=15000)
            page.wait_for_timeout(5000)  # Wait for JS to load

            anchors = page.query_selector_all("a")
            forms = page.query_selector_all("form")
            scripts = page.query_selector_all("script")

            for a in anchors:
                href = a.get_attribute("href")
                if href:
                    full = urljoin(url, href)
                    dynamic_links.add(full)

            for f in forms:
                action = f.get_attribute("action")
                if action:
                    full = urljoin(url, action)
                    dynamic_links.add(full)

            for s in scripts:
                src = s.get_attribute("src")
                if src:
                    full = urljoin(url, src)
                    dynamic_links.add(full)

        except Exception as e:
            print(f"[!] Error during headless crawl: {e}")
        finally:
            browser.close()

    return list(dynamic_links)

# ... sab functions yaha honge ...

# Example usage for testing
if __name__ == "__main__":
    url = input("Enter target URL: ").strip()
    links = extract_dynamic_links(url)

    print("\n📍 Dynamic Links Found:")
    for link in links:
        print(" -", link)