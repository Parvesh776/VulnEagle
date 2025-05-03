# recon/__init__.py

# --- JS Endpoint Scraper ---
from js_scraper import (
    extract_js_urls_from_html,
    extract_endpoints_from_js,
    scrape_js_endpoints,
)

# --- Headless Crawler ---
from headless_crawler import extract_dynamic_links as headless_crawl

# --- Playwright Crawler ---
from playwright_crawler import extract_dynamic_links as playwright_crawl

# --- Subdomain Enumerator ---
from subdomain_enum import SubdomainEnumerator

# --- Smart Recon Unified Function ---
from smart_recon import smart_recon

from crtsh_enum import fetch_subdomains
__all__ = [
    "extract_js_urls_from_html",
    "extract_endpoints_from_js",
    "scrape_js_endpoints",
    "headless_crawl",
    "playwright_crawl",
    "SubdomainEnumerator",
    "smart_recon",
    "fetch_subdomains"
]
