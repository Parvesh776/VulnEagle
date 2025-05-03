from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse
import re

def extract_dynamic_links(url):
    dynamic_links = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            print(f"[+] Crawling: {url}")
            page.goto(url, timeout=20000)
            page.wait_for_load_state('networkidle')

            # Extract links
            anchors = page.query_selector_all("a")
            forms = page.query_selector_all("form")
            scripts = page.query_selector_all("script")

            for a in anchors:
                href = a.get_attribute("href")
                if href:
                    dynamic_links.add(urljoin(url, href))

            for f in forms:
                action = f.get_attribute("action")
                if action:
                    dynamic_links.add(urljoin(url, action))

            for s in scripts:
                src = s.get_attribute("src")
                if src:
                    dynamic_links.add(urljoin(url, src))

        except Exception as e:
            print(f"[!] Error during headless crawl: {e}")
        finally:
            context.close()
            browser.close()

    # Filter out invalid/malformed URLs
    cleaned_links = {link for link in dynamic_links if urlparse(link).netloc}
    return sorted(cleaned_links)

if __name__ == "__main__":
    url = input("Enter target URL: ").strip()
    links = extract_dynamic_links(url)

    print("\n📍 Dynamic Links Found:")
    for link in links:
        print(" -", link)
