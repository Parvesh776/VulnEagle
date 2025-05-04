import argparse
import datetime
import json
from recon.smart_recon import smart_recon
from recon.js_scraper import main as js_main
from recon.crtsh_enum import fetch_subdomains
from scanner.fuzz_engine import fuzz_payloads
from scanner.vuln_mapper import map_inputs, HeaderCookieTokenMapper
from scanner.misconfig_detector import MisconfigDetector
from report.html_report import generate_html_report
from auth.session_handler import SessionHandler
from scanner.waf_detector import detect_waf  # ✅ Import WAF detection


def parse_custom_headers(header_args):
    headers = {}
    if header_args:
        for h in header_args:
            if ":" in h:
                key, val = h.split(":", 1)
                headers[key.strip()] = val.strip()
    return headers


def main():
    parser = argparse.ArgumentParser(
        description="🦅 VulnEagle - Web App Recon & Pentest CLI Tool",
        epilog="""

optional arguments:
  -h, --help                  Show this help message and exit

Target:
  --url URL                  Target URL to scan (required)

Modules:
  --smart-recon              Perform smart recon (JS parsing, dynamic crawling, subdomain enumeration)
  --map-inputs               Map input fields, headers, cookies, and tokens for vulnerability analysis
  --fuzz                     Run fuzzing engine (XSS, SQLi, LFI, SSTI) on discovered input points
  --waf                      Enable basic WAF detection and signature evasion

Authentication:
  --auth AUTH                Provide authentication header (e.g., "Bearer <token>", "Cookie: sessionid=abc")
  --header HEADER            Custom headers (e.g., "X-Forwarded-For: 127.0.0.1")
  --token TOKEN              JWT, API key, or session token to include

Reporting:
  --report-format FORMAT     Report format: html (default), json, txt
  --output FILE              Output file for the report (e.g., report.html)
Examples:
  python vulneagle.py --url https://target.com --smart-recon --output recon.html
  python vulneagle.py --url https://target.com --map-inputs --auth "Cookie: sessionid=abc" --output map.html
  python vulneagle.py --url https://target.com --fuzz --token "Bearer eyJ..." --output fuzz.html
  python vulneagle.py --url https://target.com --smart-recon --map-inputs --fuzz --header "X-Custom: yes" --waf --output full.html

Modules:
  [1] Smart Recon       → JS scraping, subdomain enum, dynamic crawling
  [2] Auto Input Mapping→ Forms, headers, tokens, cookies, CORS
  [3] Fuzzing Engine    → XSS, SQLi, LFI, SSTI detection with evasion
  [4] Misconfig Check   → SSRF, AWS Metadata, Open Ports
  [5] WAF Detection     → Basic WAF detection & signature adaptation
  [6] Reporting         → HTML, JSON, TXT reports

Author: @parvesh776 | Project: VulnEagle
""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--auth", help="Authentication cookie string or file")
    parser.add_argument("--token", help="Bearer/API token for header-based auth")
    parser.add_argument("--header", action="append", help="Custom headers (Key:Value). Use multiple times for multiple headers.")
    parser.add_argument("--report-format", choices=["html", "json", "txt"], default="html", help="Output report format")
    parser.add_argument("--output", help="Output filename (without extension)")
    parser.add_argument("--map-inputs", action="store_true", help="Only run form input and auth header mapping")
    
    parser.add_argument("--smart-recon", action='store_true', help="Run smart reconnaissance only")
    parser.add_argument("--waf", action="store_true", help="Enable WAF detection")
    parser.add_argument("--fuzz", action="store_true", help="Run fuzzing engine on discovered endpoints")

    args = parser.parse_args()

    # 🔐 Setup session
    session = SessionHandler()
    if args.auth:
        session.set_cookie_auth(args.auth)
    if args.token:
        session.set_header_auth(args.token)
    if args.header:
        custom_headers = parse_custom_headers(args.header)
        session.set_custom_headers(custom_headers)

    start_time = datetime.datetime.now()
        # 🧪 Only Input Mapper mode
    if args.map_inputs:
        print("[*] Running Input Mapping Only...")
        header_mapper = HeaderCookieTokenMapper(session)
        forms = map_inputs(args.url, session)
        header_mapper.analyze_response(args.url)

        report_data = {
            "forms": forms,
            "headers": header_mapper.report()["headers"],
            "cookies": header_mapper.report()["cookies"],
            "tokens": header_mapper.report()["tokens"],
            "timestamp": {
                "start": start_time.isoformat(),
                "end": datetime.datetime.now().isoformat(),
                "duration": str(datetime.datetime.now() - start_time)
            }
        }

        output_file = args.output if args.output else "input_mapping_report"
        if args.report_format == "html":
            generate_html_report(report_data, filename=output_file + ".html")
        elif args.report_format == "json":
            with open(f"{output_file}.json", "w") as f:
                json.dump(report_data, f, indent=2)
        elif args.report_format == "txt":
            with open(f"{output_file}.txt", "w") as f:
                f.write(json.dumps(report_data, indent=2))
        print(f"[*] Input Mapping Report saved as {output_file}")
        return

    # 🔍 Smart Recon
    print("[*] Running Smart Recon...")
    smart_recon(args.url)

    if args.smart_recon:
        print("[*] Smart Recon complete.")
        return

    # 🌐 Subdomain Discovery
    print("\n🌐 [1.5] Discovering Subdomains via crt.sh...")
    parsed_domain = args.url.split("://")[-1].split("/")[0]
    subdomains = fetch_subdomains(parsed_domain)
    subdomain_urls = [f"https://{sd}" for sd in subdomains if not sd.startswith("*")]

    # ✅ Targets to scan
    fuzz_results = []
    all_form_data = []
    header_mapper = HeaderCookieTokenMapper(session)
    scan_targets = set([args.url] + subdomain_urls)

    if args.fuzz:
     for base_url in scan_targets:
        print(f"\n[*] Crawling JS from: {base_url}")
        js_endpoints = js_main(base_url)
        js_full_urls = [f"{base_url.rstrip('/')}/{ep.lstrip('/')}" for ep in js_endpoints]

        print(f"[*] Fuzzing endpoints at: {base_url}")
        for vuln in ["xss", "sqli", "lfi", "ssti"]:
            fuzz_results.extend(fuzz_payloads(js_full_urls, vuln, session=session))


    for base_url in scan_targets:
        print(f"\n[*] Crawling JS from: {base_url}")
        js_endpoints = js_main(base_url)
        js_full_urls = [f"{base_url.rstrip('/')}/{ep.lstrip('/')}" for ep in js_endpoints]

        print(f"[*] Fuzzing endpoints at: {base_url}")
        for vuln in ["xss", "sqli", "lfi", "ssti"]:
            fuzz_results.extend(fuzz_payloads(js_full_urls, vuln, session=session))

        print(f"[*] Mapping inputs + headers for: {base_url}")
        forms = map_inputs(base_url, session)
        all_form_data.extend(forms)
        header_mapper.analyze_response(base_url)

    # 🔐 Misconfig Detection
    print("[*] Step 4: Detecting Misconfigurations...")
    misconfig = MisconfigDetector()
    misconfig_results = misconfig.run_all_checks(args.url)
    for res in misconfig_results:
        print(res)

    # 🧱 WAF Detection (optional)
    waf_result = None
    if args.waf:
        print("[*] Running WAF Detection...")
        try:
            waf_result = detect_waf(args.url)
            if waf_result:
                print(f"[!] WAF Detected: {waf_result}")
            else:
                print("[+] No WAF detected.")
        except Exception as e:
            print(f"[!] Error during WAF detection: {e}")
            waf_result = f"Error: {str(e)}"

    # ⏱️ Timing
    end_time = datetime.datetime.now()
    duration = str(end_time - start_time)

    # 📄 Final Report
    report_data = {
         "forms": forms,
         "headers": header_mapper.report()["headers"],
         "cookies": header_mapper.report()["cookies"],
         "tokens": header_mapper.report()["tokens"],
        "misconfig": [],  # ✅ Add default empty lists
        "vulns": [],
        "waf": "Not tested",
        "timestamp": {
        "start": start_time.isoformat(),
        "end": datetime.datetime.now().isoformat(),
        "duration": str(datetime.datetime.now() - start_time)
        }
    }

    if args.waf:
        report_data["waf"] = waf_result or "None"

    output_file = args.output if args.output else "report"

    if args.report_format == "html":
        print("[*] Generating HTML Report...")
        generate_html_report(report_data, filename=output_file + ".html")

    elif args.report_format == "json":
        with open(f"{output_file}.json", "w") as f:
            json.dump(report_data, f, indent=4)
        print(f"[*] JSON report saved as {output_file}.json")

    elif args.report_format == "txt":
        with open(f"{output_file}.txt", "w") as f:
            f.write("=== VulnEagle Text Report ===\n")
            f.write(f"Scan Start: {report_data['timestamp']['start']}\n")
            f.write(f"Scan End: {report_data['timestamp']['end']}\n")
            f.write(f"Duration: {report_data['timestamp']['duration']}\n\n")
            f.write("Discovered Forms:\n")
            for form in report_data["forms"]:
                f.write(json.dumps(form, indent=2) + "\n")
            f.write("\nHeaders:\n" + json.dumps(report_data["headers"], indent=2))
            f.write("\nCookies:\n" + json.dumps(report_data["cookies"], indent=2))
            f.write("\nTokens:\n" + json.dumps(report_data["tokens"], indent=2))
            f.write("\nMisconfigurations:\n")
            for m in report_data["misconfig"]:
                f.write(f"- {m}\n")
            f.write("\nDiscovered Vulnerabilities:\n")
            for vuln in report_data["vulns"]:
                f.write(f"- {vuln}\n")
            if args.waf:
                f.write(f"\nWAF Detection Result:\n{waf_result}\n")
        print(f"[*] Text report saved as {output_file}.txt")

    print("[*] ✅ Scan Complete.")


if __name__ == "__main__":
    main()
