import argparse
from recon.smart_recon import smart_recon
from recon.js_scraper import main as js_main
from scanner.fuzz_engine import fuzz_payloads
from scanner.vuln_mapper import map_inputs
from report.html_report import generate_html_report
from auth.session_handler import SessionHandler, load_cookies_from_file
from scanner.vuln_mapper import HeaderCookieTokenMapper 

def main():
    parser = argparse.ArgumentParser(description="VulnEagle - Web App Recon & Pentest CLI Tool")

    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--auth", help="Path to the cookie file")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--report", choices=["html", "none"], default="none", help="Generate HTML report")
    parser.add_argument("--smart-recon", action='store_true', help="Run smart reconnaissance")

    args = parser.parse_args()

    # 🔐 Setup session
    session = SessionHandler()
    if args.auth:
        session.set_cookie_auth(args.auth)
    if args.token:
        session.set_header_auth(args.token)

    if args.smart_recon:
        print("[*] Running Smart Recon...")
        smart_recon(args.url)
        return

    # Step 1: JS Endpoint Discovery
    print("[*] Step 1: Extracting JS Endpoints...")
    js_endpoints = js_main(args.url)

    # Step 2: Fuzzing
    print("[*] Step 2: Fuzzing Endpoints...")
    fuzz_results = []
    for ep in js_endpoints:
        target_url = f"{args.url.rstrip('/')}/{ep.lstrip('/')}"
        fuzz_results.extend(fuzz_payloads(target_url, method="GET", params=["q"]))

    # Step 3: Map Inputs + Headers
    print("[*] Step 3: Mapping Inputs and Auth Headers...")
    all_form_data = []
    header_mapper = HeaderCookieTokenMapper(session)

    unique_urls = set([args.url] + [url for url in fuzz_results])
    for url in unique_urls:
        forms = map_inputs(url, session)
        all_form_data.extend(forms)
        header_mapper.analyze_response(url)

    # Report
    report_data = {
        "forms": all_form_data,
        "headers": header_mapper.report()["headers"],
        "cookies": header_mapper.report()["cookies"],
        "tokens": header_mapper.report()["tokens"]
    }

    if args.report == "html":
        print("[*] Generating HTML Report...")
        generate_html_report(report_data)

    print("[*] Scan Complete.")

if __name__ == "__main__":
    main()
