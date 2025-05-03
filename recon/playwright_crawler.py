import asyncio
from playwright.async_api import async_playwright
from urllib.parse import urljoin, urlparse
import re

async def extract_dynamic_links(url):
    links = set()
    scripts = set()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        print(f"[*] Visiting: {url}")
        await page.goto(url, timeout=60000)

        # Wait for network to be idle
        await page.wait_for_load_state('networkidle')

        # Extract href links
        anchors = await page.eval_on_selector_all("a", "elements => elements.map(el => el.href)")
        links.update(anchors)

        # Extract JavaScript files
        js_files = await page.eval_on_selector_all("script[src]", "elements => elements.map(el => el.src)")
        scripts.update(js_files)

        await browser.close()

    # Filter out empty or malformed URLs
    cleaned_links = {link for link in links if link and urlparse(link).netloc}
    cleaned_scripts = {js for js in scripts if js and js.endswith(".js")}
    
    return cleaned_links, cleaned_scripts

# CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python playwright_crawler.py <url>")
    else:
        url = sys.argv[1]
        results = asyncio.run(extract_dynamic_links(url))
        print("\n[+] Discovered Links:")
        for link in results[0]:
            print(link)

        print("\n[+] Discovered JS Files:")
        for js in results[1]:
            print(js)