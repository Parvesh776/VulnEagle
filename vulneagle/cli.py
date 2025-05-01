import argparse
from recon.smart_recon import smart_recon
from recon.js_scraper import main as js_main
from scanner.fuzz_engine import fuzz_payloads
from scanner.vuln_mapper import map_inputs
from report.html_report import generate_html_report
from auth.session_handler import load_cookies_from_file

def main():
    parser = argparse.ArgumentParser(description="VulnEagle - Web App Recon & Pentest CLI Tool")

    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--auth", help="Path to the cookie file")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--report", choices=["html", "none"], default="none", help="Generate HTML report")
    parser.add_argument("--smart-recon", action='store_true', help="Run smart reconnaissance")

    args = parser.parse_args()

    headers = {}
    cookies = {}

    if args.auth:
        cookies = load_cookies_from_file(args.auth)
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    if args.smart_recon:
        print("[*] Running Smart Recon...")
        smart_recon(args.url)
        return

    # Default JS Endpoint Discovery + Fuzzing
    print("[*] Step 1: Extracting JS Endpoints...")
    js_endpoints = js_main(args.url)

    print("[*] Step 2: Fuzzing Endpoints...")
    fuzz_results = []
    for ep in js_endpoints:
        target_url = f"{args.url.rstrip('/')}/{ep.lstrip('/')}"
        fuzz_results.extend(fuzz_payloads(target_url, method="GET", params=["q"]))

    print("[*] Step 3: Mapping Vulnerabilities...")
    vulnerability_report = map_inputs(fuzz_results)

    if args.report == "html":
        print("[*] Generating HTML Report...")
        generate_html_report(vulnerability_report)

    print("[*] Scan Complete.")

if __name__ == "__main__":
    main()