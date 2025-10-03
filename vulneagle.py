#!/usr/bin/env python3
# VulnEagle - Fast Passive & Brute Recon Tool
# Optimized for Kali Linux

import argparse
import datetime
import json
import re
import time
import sys
import os
import signal
import concurrent.futures
import requests
from urllib.parse import urlparse
from recon.crtsh_enum import fetch_subdomains
from recon.subdomain_bruteforcer import bruteforce_subdomains
from scanner.dir_bruteforcer import dir_bruteforce, recursive_dir_bruteforce
from auth.session_handler import SessionHandler


__version__ = "0.4.0"

# Global flag for graceful shutdown
_shutdown_requested = False
_force_quit = False

def _handle_shutdown(signum, frame):
    """Handle CTRL+C gracefully"""
    global _shutdown_requested, _force_quit
    if not _shutdown_requested:
        _shutdown_requested = True
        print("\n[!] Shutdown requested - finishing current operations...")
        print("[!] Press CTRL+C again to force quit")
    else:
        _force_quit = True
        print("\n[!] Force quit")
        os._exit(130)

# Register signal handler
signal.signal(signal.SIGINT, _handle_shutdown)

# Utility function for safe results directory creation
def _ensure_results_dir():
    """Thread-safe results directory creation"""
    results_dir = "results"
    try:
        if not os.path.exists(results_dir):
            os.makedirs(results_dir, exist_ok=True)
    except FileExistsError:
        # Another thread created it, that's fine
        pass
    except Exception as e:
        print(f"[!] Warning: Could not create results directory: {e}")
    return results_dir

# Output helper placed early so available where first referenced
def _write_enum_output(base, domain, subdomains, source_map, stats, status_map=None, live_list=None):
    args = globals().get('ARGS_LAST_PARSED')
    fmt = 'txt'
    if args:
        if getattr(args, 'json_lines', False):
            fmt = 'jsonl'
        else:
            fmt = getattr(args, 'report_format', 'txt')
    
    # Create results folder safely
    results_dir = _ensure_results_dir()
    
    # Extract filename from base path and put it in results folder
    base_filename = os.path.basename(base)
    base = os.path.join(results_dir, base_filename)
    
    ip_cache = {}
    if args and getattr(args, 'resolve_ip', False):
        import socket
        for s in subdomains:
            try:
                ip_cache[s] = socket.gethostbyname(s)
            except Exception:
                ip_cache[s] = None
    if fmt == 'jsonl':
        path = f"{base}.jsonl"
        with open(path, 'w', encoding='utf-8') as f:
            for s in subdomains:
                row = {'domain': domain, 'subdomain': s}
                if args and getattr(args, 'resolve_ip', False):
                    row['ip'] = ip_cache.get(s)
                if status_map and s in status_map:
                    row['status'] = status_map[s]
                if source_map and s in source_map:
                    row['sources'] = sorted(list(source_map[s]))
                f.write(json.dumps(row) + '\n')
            if live_list:
                for entry in live_list:
                    f.write(json.dumps({'live': True, **entry}) + '\n')
        return
    if fmt == 'json':
        path = f"{base}.json"
        payload = {
            'domain': domain,
            'count': len(subdomains),
            'subdomains': subdomains,
        }
        if status_map:
            payload['status'] = status_map
        if live_list:
            payload['live'] = live_list
        if source_map:
            payload['sources'] = {k: sorted(list(v)) for k, v in source_map.items()}
        if args and getattr(args, 'resolve_ip', False):
            payload['ip'] = {k: v for k, v in ip_cache.items() if v}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
        return
    path = f"{base}.txt"
    with open(path, 'w', encoding='utf-8') as f:
        for s in subdomains:
            if status_map and s in status_map and status_map[s].get('status') is not None:
                st = status_map[s]
                f.write(f"{s} {st['status']} {st.get('scheme','')}\n")
            else:
                f.write(f"{s}\n")
        if live_list:
            f.write("\n# Live Hosts\n")
            for entry in live_list:
                f.write(f"{entry['status']} {entry['url']}\n")


def main():
    class CompactFormatter(argparse.RawTextHelpFormatter):
        def _format_action_invocation(self, action):
            if not action.option_strings:
                return super()._format_action_invocation(action)
            parts = []
            for opt in action.option_strings:
                parts.append(opt)
            args_string = ''
            if action.nargs != 0:
                metavar = self._format_args(action, action.dest.upper())
                args_string = ' ' + metavar
            return ', '.join(parts) + args_string

    parser = argparse.ArgumentParser(
        prog="vulneagle.py",
        usage="%(prog)s -d <domain> [MODE] [OPTIONS]",
        description="VulnEagle v0.4.0 - Fast passive & brute recon with 39 sources.\n"
                    "All results auto-save to results/ folder. CTRL+C for graceful exit.\n"
                    "Use --long-help for detailed examples.",
        formatter_class=CompactFormatter,
    
               
    )

    # Simplified group names
    g_target = parser.add_argument_group("TARGETS")
    g_sources = parser.add_argument_group("SOURCES")
    g_wordlists = parser.add_argument_group("WORDLISTS")
    g_perf = parser.add_argument_group("PERF")
    g_filter = parser.add_argument_group("FILTER")
    g_probe = parser.add_argument_group("PROBE")
    g_output = parser.add_argument_group("OUTPUT")
    g_misc = parser.add_argument_group("MISC")

    # Target & Modes
    g_target.add_argument("-d", "-domain", dest="targets", action="append", required=False,
                          help="Target domain (repeatable). Required unless -dL or -l used")
    g_target.add_argument("-dL", "-list", dest="domain_list_file", help="File with domains (one per line)")
    g_target.add_argument("-se", "--subdomain-enum", action="store_true", help="Passive enum (39 APIs)")
    g_target.add_argument("-u", "--url", "--target", dest="legacy_targets", action="append", required=False, help=argparse.SUPPRESS)
    g_target.add_argument("-sb", "--subdomain-bruteforce", action="store_true", help="DNS brute (needs -w & -rf)")
    g_target.add_argument("-db", "--dir-bruteforce", action="store_true", help="Dir brute (needs -w, supports -mc)")
    g_target.add_argument("-l", "-host-list", dest="host_list_file", help="File with hosts (one per line) for probe/status mode")

    # Sources
    g_sources.add_argument("-s", "-sources", dest="include_sources", action="append", help="Only these sources (comma-separated)")
    g_sources.add_argument("-es", "-exclude-sources", dest="exclude_sources", action="append", help="Exclude sources (comma-separated)")
    g_sources.add_argument("-all", action="store_true", dest="all_sources", help="Use all 39 sources (default)")
    g_sources.add_argument("--lite", action="store_true", dest="lite_sources", help="Only 11 free sources (no API keys)")
    g_sources.add_argument("-ls", "-list-sources", action="store_true", dest="list_sources", help="List all 39 sources & exit")
    g_sources.add_argument("-recursive", action="store_true", dest="recursive_sources", help="Recursive-capable sources only")

    # Wordlists
    g_wordlists.add_argument("-w", "--wordlist", help="Wordlist for -sb (subdomains) or -db (directories)")
    g_wordlists.add_argument("--resolver-file", "-rf", help="DNS resolvers file (required for -sb)")

    # Performance
    g_perf.add_argument("-t", "--threads", dest="threads", type=int, default=50, help="Concurrent threads (default: 50)")
    g_perf.add_argument("-dt", "--dns-timeout", type=float, default=2.0, help="DNS query timeout in seconds (default: 2.0)")
    g_perf.add_argument("-dto", "--dir-timeout", type=float, default=5.0, help="Directory request timeout in seconds (default: 5.0)")
    g_perf.add_argument("--rate-limit", type=int, help="Rate limit for directory brute (req/sec)")
    g_perf.add_argument("--no-head", action="store_true", help="Disable HEAD requests in dir brute (use GET only)")
    g_perf.add_argument("--recursion", action="store_true", help="Enable recursive directory brute force")
    g_perf.add_argument("--rec-depth", type=int, default=2, help="Recursive depth 1-5 (default: 2)")
    g_perf.add_argument("-dx", "--dir-extensions", help="Directory extensions (.php,.bak,...)")
    g_perf.add_argument("-ds", "--dir-status", help="Directory success status codes (default: 200,204,301,302,307,401,403)")

    # Filtering
    g_filter.add_argument("-m", "-match", dest="match_filters", action="append", help="Keep subdomains matching patterns/file")
    g_filter.add_argument("-f", "-filter", dest="exclude_filters", action="append", help="Exclude subdomains matching patterns/file")
    g_filter.add_argument("-mc", "--match-code", help="Keep only HTTP status codes (200,403,...)\n"
                                                       "Works in: -se (enum), -sb (brute), -db (dir brute)")

    # Probe
    g_probe.add_argument("-sc", "--status-code", action="store_true", help="Probe HTTP/HTTPS status codes")
    g_probe.add_argument("-live", "--live", action="store_true", help="Output only live/reachable hosts")
    g_probe.add_argument("-rr", "--request", dest="raw_request_file", help="Replay raw HTTP request against each host")

    # Output
    g_output.add_argument("-o", "--output", help="Output filename prefix (auto-saves to results/ folder)")
    g_output.add_argument("-oD", "-output-dir", dest="output_dir", help="Output directory for -dL batch mode (default: results/)")
    g_output.add_argument("-r", "--report-format", choices=["txt", "json", "jsonl"], default="txt", help="Output format (default: txt)")
    g_output.add_argument("-oJ", "-json", dest="json_lines", action="store_true", help="Force JSONL output")
    g_output.add_argument("-cs", "-collect-sources", action="store_true", dest="collect_sources", help="Include source attribution in JSON/JSONL")
    g_output.add_argument("-oI", "-ip", action="store_true", dest="resolve_ip", help="Resolve & include IP addresses")

    # Misc
    g_misc.add_argument("--version", action="store_true", help="Show version and exit")
    g_perf.add_argument("-timeout", type=int, default=60, help="Per-source soft timeout in seconds (default: 60)")
    g_perf.add_argument("-max-time", type=int, default=600, help="Overall enumeration timeout in seconds (default: 600)")
    g_misc.add_argument("--resolver-check", action="store_true", help="Validate resolvers via UDP/53 probe")
    g_misc.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (minimal output)")
    g_misc.add_argument("-v", "--verbose", action="store_true", help="Verbose mode (extra diagnostics)")
    g_misc.add_argument("--long-help", action="store_true", help="Show extended examples and exit")

    # Parse args
    args = parser.parse_args()
    # Extended help block printed on demand
    EXTENDED_HELP = (
        "\n" + "="*70 + "\n"
        "VulnEagle v0.4.0 - Extended Usage Examples\n"
        "="*70 + "\n\n"
        "🎯 KEY FEATURES:\n"
        "  • 39 enumeration sources (11 free + 28 premium)\n"
        "  • Status code filtering with -mc flag\n"
        "  • Auto-save to results/ folder\n"
        "  • Graceful CTRL+C shutdown (press once to save, twice to force)\n\n"
        "📋 BASIC EXAMPLES:\n\n"
        "  1. List all 39 sources:\n"
        "     python vulneagle.py -ls\n\n"
        "  2. Subdomain enumeration (all sources):\n"
        "     python vulneagle.py -d example.com -se -all\n\n"
        "  3. Enum with live filtering + status codes:\n"
        "     python vulneagle.py -d example.com -se -sc -live -mc 200,403\n\n"
        "  4. DNS brute force:\n"
        "     python vulneagle.py -d example.com -sb -w wordlists/subdomains.txt \\\n"
        "       --resolver-file wordlists/resolvers.txt\n\n"
        "  5. DNS brute + status filtering:\n"
        "     python vulneagle.py -d example.com -sb -w wordlists/subdomains.txt \\\n"
        "       -rf wordlists/resolvers.txt -sc -mc 200,302\n\n"
        "  6. Directory brute force:\n"
        "     python vulneagle.py -d https://app.example.com -db \\\n"
        "       -w wordlists/directories.txt -mc 200,403\n\n"
        "  7. Recursive directory brute:\n"
        "     python vulneagle.py -d https://app.example.com -db \\\n"
        "       -w wordlists/directories.txt --recursion --rec-depth 3 -mc 200\n\n"
        "📤 OUTPUT EXAMPLES:\n\n"
        "  8. JSON output with source tracking:\n"
        "     python vulneagle.py -d example.com -se -all -r json -cs -o results\n\n"
        "  9. JSONL output with IP resolution:\n"
        "     python vulneagle.py -d example.com -se -all -r jsonl -cs -oI -o scan\n\n"
        "  10. Batch multiple domains:\n"
        "      python vulneagle.py -dL domains.txt -se -all -oD results/batch\n\n"
        "🔍 ADVANCED FILTERING:\n\n"
        "  11. Only free sources (no API keys):\n"
        "      python vulneagle.py -d example.com -se --lite\n\n"
        "  12. Specific sources only:\n"
        "      python vulneagle.py -d example.com -se -s crtsh,bufferover,wayback\n\n"
        "  13. Exclude certain sources:\n"
        "      python vulneagle.py -d example.com -se -all -es shodan,virustotal\n\n"
        "  14. Pattern matching:\n"
        "      python vulneagle.py -d example.com -se -m admin,api,dev\n\n"
        "  15. Pattern filtering (exclude):\n"
        "      python vulneagle.py -d example.com -se -f test,staging\n\n"
        "🌐 PROBE & STATUS:\n\n"
        "  16. Probe existing hosts:\n"
        "      python vulneagle.py -l hosts.txt -sc -live\n\n"
        "  17. Probe with status filtering:\n"
        "      python vulneagle.py -l hosts.txt -sc -mc 200,302,403 -live\n\n"
        "  18. Raw request replay:\n"
        "      python vulneagle.py -l hosts.txt -rr request.txt -sc -mc 200\n\n"
        "⚙️ API CONFIGURATION:\n\n"
        "  Method 1 - Config File:\n"
        "    cp provider-config.yaml.example recon/provider-config.yaml\n"
        "    nano recon/provider-config.yaml  # Add your API keys\n\n"
        "  Method 2 - Environment Variables:\n"
        "    export VE_VIRUSTOTAL_KEY='your-key'\n"
        "    export VE_SHODAN_KEY='your-key'\n"
        "    export VE_SECURITYTRAILS_KEY='your-key'\n\n"
        "📁 OUTPUT LOCATIONS:\n"
        "  • All results save to: results/ folder\n"
        "  • Format: results/<output_prefix>.txt|json|jsonl\n"
        "  • Batch mode: results/<output_dir>/<domain>.txt\n\n"
        "🔑 NEW IN v0.4.0:\n"
        "  ✓ 39 sources (added BufferOver, CommonCrawl)\n"
        "  ✓ -mc flag for status code filtering (all modes)\n"
        "  ✓ Auto-save to results/ folder\n"
        "  ✓ Graceful CTRL+C shutdown\n"
        "  ✓ -ls works without domain\n"
        "  ✓ Thread-safe file operations\n\n"
        "📝 NOTES:\n"
        "  • Press CTRL+C once for graceful exit (saves results)\n"
        "  • Press CTRL+C twice to force quit\n"
        "  • Use -q for quiet mode, -v for verbose\n"
        "  • -mc works in: subdomain enum, subdomain brute, directory brute\n\n"
        "🔗 MORE INFO:\n"
        "  GitHub: https://github.com/Parvesh776/VulnEagle\n"
        "  Docs: See README.md for detailed documentation\n"
        "="*70 + "\n"
    )
    
    if getattr(args, 'long_help', False):
        print(EXTENDED_HELP)
        return 0
    # store globally for helper access
    globals()['ARGS_LAST_PARSED'] = args

    if args.version:
        print(f"VulnEagle {__version__}")
        return 0

    # Handle list_sources early (no target needed)
    if args.list_sources:
        fetch_subdomains(None, list_sources=True)
        return 0

    # Validate presence of at least one target for modes that need it later.
    # Merge legacy -u targets into new list
    if args.legacy_targets:
        if not args.targets:
            args.targets = []
        args.targets.extend(args.legacy_targets)
    if not args.targets and not args.domain_list_file and not args.host_list_file:
        print("[!] Error: provide at least one -d / -domain, a -dL list file, or a host list (-l)")
        return 2

    start_time = datetime.datetime.now()
    start_epoch = time.time()
    session = SessionHandler()

    # Simple color helper (falls back if no ANSI support)
    class C:
        R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"; M = "\033[35m"; C = "\033[36m"; W = "\033[37m"; RS = "\033[0m"

    def color(txt, col):
        if sys.stdout.isatty():
            return col + txt + C.RS
        return txt

    def log(msg, level="info"):
        if args.quiet and level not in ("result", "summary", "error"):
            return
        palette = {
            "info": C.C,
            "ok": C.G,
            "warn": C.Y,
            "error": C.R,
            "result": C.M,
            "summary": C.B,
        }
        col = palette.get(level, C.W)
        print(color(msg, col))

    def verbose(msg):
        if args.verbose and not args.quiet:
            log(msg, "info")

    # Banner
    if not args.quiet:
        banner_lines = [
            color('┌──────────────────────────────────────────────┐', C.B),
            f"{color('│', C.B)} {color('VulnEagle', C.M)} - Web Scanner {color('(lightweight)', C.C)} {color('│', C.B)}",
            f"{color('│', C.B)} Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')} {color('│', C.B)}",
            color('└──────────────────────────────────────────────┘', C.B)
        ]
        print("\n".join(banner_lines))

    # Helper: normalize/extract domain
    def extract_domain(raw):
        if not raw:
            return None
        # Add scheme if missing for urlparse reliability
        if not raw.startswith(('http://', 'https://')):
            candidate = 'http://' + raw
        else:
            candidate = raw
        parsed = urlparse(candidate)
        host = parsed.netloc.split(':')[0]
        return host.lower().strip('.') if host else None

    def read_resolvers_file(path):
        resolvers = []
        if not path:
            return resolvers
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    resolvers.append(line)
        except FileNotFoundError:
            print(f"[!] Resolver file not found: {path}")
        except Exception as e:
            print(f"[!] Error reading resolver file: {e}")
        return resolvers

    def validate_resolvers(resolvers):
        valid = []
        ip_regex = re.compile(r'^((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.|$)){4}$')
        for r in resolvers:
            if ip_regex.match(r):
                valid.append(r)
            else:
                print(f"[!] Skipping invalid resolver entry: {r}")
        deduped = list(dict.fromkeys(valid))
        # Optional UDP 53 reachability check
        if args.resolver_check and deduped:
            import socket
            reachable = []
            for ip in deduped:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.6)
                    # Send minimal DNS header (query for '.') to port 53
                    payload = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01\x00\x01'
                    sock.sendto(payload, (ip, 53))
                    # Not waiting for full response; try recv (non-fatal if none)
                    try:
                        sock.recvfrom(512)
                    except Exception:
                        pass
                    reachable.append(ip)
                except Exception:
                    print(f"[!] Resolver unreachable (UDP/53): {ip}")
                finally:
                    try: sock.close()
                    except Exception: pass
            return reachable
        return deduped

    DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]  # kept for informational hints

    def ensure_file(path, purpose):
        if not path:
            return False, f"Missing {purpose} path"
        if not os.path.isfile(path):
            return False, f"{purpose} file not found: {path}"
        return True, None

    # Validate target
    # Resolve primary domain (first target) for enum/brute/dir modes
    primary_domain = None
    if args.targets:
        primary_domain = extract_domain(args.targets[0])
    if any([args.subdomain_enum, args.subdomain_bruteforce, args.dir_bruteforce]) and not args.domain_list_file:
        if not primary_domain or '.' not in primary_domain:
            print("[!] A valid primary domain (-d) is required for enumeration/brute modes.")
            return

    # Ensure at least one action flag
    # If no core mode chosen, but user wants status/live probing on provided hosts -> enter probe mode later.
    core_mode_selected = any([args.subdomain_enum, args.subdomain_bruteforce, args.dir_bruteforce])
    if not core_mode_selected and not (args.status_code or args.live or args.raw_request_file or args.match_code):
        print("[!] Select a mode: -se, -sb, -db OR use -sc / -live / -rr with -u/-l for probe mode")
        return
    # Basic numeric sanity
    if args.threads < 1:
        log("[!] Adjusting threads to 1 (invalid provided)", "warn")
        args.threads = 1
    enum_results = []
    brute_results = []
    status_map = {}

    def probe_status(subdomains, timeout=5, threads=30):
        """Probe HTTP status for each subdomain using HTTPS first then HTTP fallback.
        Returns dict: subdomain -> (scheme, status or None)
        """
        results = {}
        subs = [s for s in subdomains if s and not s.startswith('*')]
        if not subs:
            return results
        max_threads = min(threads, 50)

        def check(host):
            schemes = ["https://", "http://"]
            for sch in schemes:
                url = sch + host
                try:
                    # HEAD first
                    r = requests.head(url, timeout=timeout, allow_redirects=True)
                    code = r.status_code
                    # Some servers mis-handle HEAD; fallback to GET if suspicious
                    if code in (405, 500):
                        try:
                            r2 = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
                            code = r2.status_code
                        except Exception:
                            pass
                    return host, sch.rstrip(':/'), code
                except Exception:
                    continue
            return host, None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
            for host, scheme, code in ex.map(check, subs):
                results[host] = {"scheme": scheme, "status": code}
        return results
    dir_results = {}


    # Helper loaders for match/filter patterns
    def _load_pattern_inputs(values):
        patterns = set()
        if not values:
            return patterns
        for item in values:
            if not item:
                continue
            if os.path.isfile(item):
                try:
                    with open(item, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                patterns.add(line.lower())
                except Exception:
                    pass
                continue
            for part in item.split(','):
                part = part.strip()
                if part:
                    patterns.add(part.lower())
        return patterns

    match_set = _load_pattern_inputs(getattr(args, 'match_filters', None))
    exclude_set = _load_pattern_inputs(getattr(args, 'exclude_filters', None))

    def _apply_match_filter(subs):
        if not match_set:
            return subs
        return [s for s in subs if any(m in s for m in match_set)]

    def _apply_exclude_filter(subs):
        if not exclude_set:
            return subs
        return [s for s in subs if not any(f in s for f in exclude_set)]

    def _set_from_args(values):
        if not values:
            return None
        out = set()
        for v in values:
            if not v: continue
            for part in v.split(','):
                part = part.strip().lower()
                if part:
                    out.add(part)
        return out or None

    # Domain list file support
    domain_list = []
    if getattr(args, 'domain_list_file', None):
        try:
            with open(args.domain_list_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        dom = extract_domain(line)
                        if dom:
                            domain_list.append(dom)
        except Exception as e:
            log(f"[!] Failed reading domain list: {e}", "error")
            return

    # Subdomain Enumeration Mode
    if args.subdomain_enum:
        log("[*] Subdomain Enumeration (CTRL+C to stop)")
        try:
            # Multi-domain batch mode
            if domain_list:
                out_dir = getattr(args, 'output_dir', None)
                # Default to results folder if no output_dir specified
                if not out_dir:
                    out_dir = _ensure_results_dir()
                elif not os.path.isdir(out_dir):
                    os.makedirs(out_dir, exist_ok=True)
                for dom in domain_list:
                    log(f"\n[=] Enumerating {dom}")
                    _inc = _set_from_args(getattr(args, 'include_sources', None))
                    _exc = _set_from_args(getattr(args, 'exclude_sources', None))
                    effective_all = True if not args.lite_sources and not _inc and not _exc and not getattr(args, 'all_sources', False) else getattr(args, 'all_sources', False)
                    res = fetch_subdomains(
                        dom,
                        include=_inc,
                        exclude=_exc,
                        all_sources=effective_all,
                        list_sources=False,
                        parallel=True,
                        max_workers=30,
                        shuffle=False,
                        return_stats=getattr(args, 'collect_sources', False),
                        collect_map=getattr(args, 'collect_sources', False),
                        timeout=getattr(args, 'timeout', None),
                        max_time=getattr(args, 'max_time', None),
                        recursive_only=getattr(args, 'recursive_sources', False),
                    )
                    if getattr(args, 'collect_sources', False):
                        if len(res) == 3:
                            sub_list, stats, source_map = res
                        else:
                            sub_list, stats = res
                            source_map = {}
                    else:
                        sub_list = res
                        stats = []
                        source_map = {}
                    sub_list = _apply_exclude_filter(_apply_match_filter(sub_list))
                    status_map_local = {}
                    live_list_local = None
                    if (args.status_code or args.live or args.match_code) and sub_list:
                        log("[*] Probing HTTP status codes")
                        status_map_local = probe_status(sub_list, threads=min(args.threads, 60))
                        
                        # Apply match code filtering if specified
                        match_codes = None
                        if args.match_code:
                            match_codes = {c.strip() for c in args.match_code.split(',') if c.strip()}
                        
                        if args.live or args.match_code:
                            live_list_local = []
                            filtered_subs = []
                            for s in sub_list:
                                meta = status_map_local.get(s, {})
                                status = meta.get('status')
                                scheme = meta.get('scheme')
                                
                                if status is None or not scheme:
                                    continue
                                
                                # Apply match code filter
                                if match_codes and str(status) not in match_codes:
                                    continue
                                
                                filtered_subs.append(s)
                                live_list_local.append({
                                    "host": s,
                                    "scheme": scheme,
                                    "status": status,
                                    "url": f"{scheme}://{s}"
                                })
                            
                            # Update sub_list to filtered results if match_code is used
                            if match_codes:
                                sub_list = filtered_subs
                    
                    base = os.path.join(out_dir, dom) if out_dir else (args.output or f"{dom}_subdomains")
                    _write_enum_output(base, dom, sub_list, source_map, stats, status_map=status_map_local, live_list=live_list_local)
                log("\n[OK] Completed batch enumeration", "summary")
                return

            if len(args.targets or []) > 1:
                log(f"[!] Multiple targets provided. Using first for enumeration: {primary_domain}", "warn")
            _inc = _set_from_args(getattr(args, 'include_sources', None))
            _exc = _set_from_args(getattr(args, 'exclude_sources', None))
            effective_all = True if not args.lite_sources and not _inc and not _exc and not getattr(args, 'all_sources', False) else getattr(args, 'all_sources', False)
            res = fetch_subdomains(
                primary_domain,
                include=_inc,
                exclude=_exc,
                all_sources=effective_all,
                list_sources=False,
                parallel=True,
                max_workers=30,
                shuffle=False,
                return_stats=getattr(args, 'collect_sources', False),
                collect_map=getattr(args, 'collect_sources', False),
                timeout=getattr(args, 'timeout', None),
                max_time=getattr(args, 'max_time', None),
                recursive_only=getattr(args, 'recursive_sources', False),
            )
            if getattr(args, 'collect_sources', False):
                if len(res) == 3:
                    enum_results, stats, source_map = res
                else:
                    enum_results, stats = res
                    source_map = {}
            else:
                enum_results = res
                stats = []
                source_map = {}
            enum_results = _apply_exclude_filter(_apply_match_filter(enum_results))
            log(f"\n[OK] Found {len(enum_results)} subdomains (enumeration)\n", "ok")
            for idx, sub in enumerate(enum_results, 1):
                log(f"{idx}. {sub}", "result")
            
            live_enum = None
            status_map = {}
            if (args.status_code or args.live or args.match_code) and enum_results:
                log("[*] Probing HTTP status codes for enumerated subdomains")
                status_map = probe_status(enum_results, threads=min(args.threads, 60))
                
                # Apply match code filtering if specified
                match_codes = None
                if args.match_code:
                    match_codes = {c.strip() for c in args.match_code.split(',') if c.strip()}
                    log(f"[*] Filtering by status codes: {', '.join(sorted(match_codes))}", "info")
                
                if args.live or args.match_code:
                    live_enum = []
                    filtered_results = []
                    for s in enum_results:
                        meta = status_map.get(s, {})
                        status = meta.get('status')
                        scheme = meta.get('scheme')
                        
                        if status is None or not scheme:
                            continue
                        
                        # Apply match code filter
                        if match_codes and str(status) not in match_codes:
                            continue
                        
                        filtered_results.append(s)
                        live_enum.append({
                            "host": s,
                            "scheme": scheme,
                            "status": status,
                            "url": f"{scheme}://{s}"
                        })
                    
                    if match_codes:
                        log(f"[*] Matched hosts (filtered by status): {len(filtered_results)}", "info")
                        # Update enum_results to only include filtered results
                        enum_results = filtered_results
                    else:
                        log(f"[*] Live hosts: {len(live_enum)}", "info")
                
                for s in enum_results:
                    meta = status_map.get(s, {})
                    if meta.get("status") is not None:
                        log(f"    {s} -> {meta['status']} ({meta['scheme']})", "info")
            
            output = args.output or f"{primary_domain}_subdomains"
            _write_enum_output(output, primary_domain, enum_results, source_map, stats, status_map=status_map, live_list=live_enum if (args.live or args.match_code) else None)
            log(f"\n[*] Saved to {output}.{('jsonl' if args.report_format=='jsonl' or args.json_lines else args.report_format)}", "ok")
            return
        except KeyboardInterrupt:
            log("\n[!] Stopped by user", "warn")
            return

    # Subdomain Brute-Force Mode
    if args.subdomain_bruteforce:
        log("[*] Subdomain Brute-Force Mode (CTRL+C to stop)")
        try:
            wordlist = args.wordlist or "wordlists/subdomains.txt"
            if not args.wordlist:
                # Provide hint if user forgot custom list
                verbose("[i] Using default fallback subdomain wordlist path (consider specifying -w)")
            ok_w, err = ensure_file(wordlist, "subdomain wordlist")
            if not ok_w:
                log(f"[!] {err}", "error"); return
            if not args.resolver_file:
                log("[!] Provide resolvers with --resolver-file", "error")
                return
            file_resolvers = read_resolvers_file(args.resolver_file)
            validated = validate_resolvers(file_resolvers)
            if not validated:
                log("[!] Resolver file empty or invalid entries only.", "error")
                return

            brute_results = bruteforce_subdomains(primary_domain, wordlist, threads=args.threads, resolvers=validated, timeout=args.dns_timeout)

            log(f"\n[OK] Found {len(brute_results)} subdomains (brute-force)\n", "ok")
            for idx, sub in enumerate(brute_results, 1):
                log(f"{idx}. {sub}", "result")

            live_brute = None
            status_map = {}
            if (args.status_code or args.live or args.match_code) and brute_results:
                log("[*] Probing HTTP status codes for brute-forced subdomains")
                status_map = probe_status(brute_results, threads=min(args.threads, 60))
                
                # Apply match code filtering if specified
                match_codes = None
                if args.match_code:
                    match_codes = {c.strip() for c in args.match_code.split(',') if c.strip()}
                    log(f"[*] Filtering by status codes: {', '.join(sorted(match_codes))}", "info")
                
                filtered_results = []
                if args.live or args.match_code:
                    live_brute = []
                    for s in brute_results:
                        meta = status_map.get(s, {})
                        status = meta.get('status')
                        scheme = meta.get('scheme')
                        
                        if status is None or not scheme:
                            continue
                        
                        # Apply match code filter
                        if match_codes and str(status) not in match_codes:
                            continue
                        
                        filtered_results.append(s)
                        live_brute.append({
                            "host": s,
                            "scheme": scheme,
                            "status": status,
                            "url": f"{scheme}://{s}"
                        })
                    
                    if match_codes:
                        log(f"[*] Matched hosts (filtered by status): {len(filtered_results)}", "info")
                    else:
                        log(f"[*] Live hosts: {len(live_brute)}", "info")
                    
                    # Use filtered results for output
                    brute_results = filtered_results if filtered_results else brute_results
                else:
                    live_brute = None
                
                for s in (filtered_results if filtered_results else brute_results):
                    meta = status_map.get(s, {})
                    if meta.get("status") is not None:
                        log(f"    {s} -> {meta['status']} ({meta['scheme']})", "info")

            output = args.output or f"{primary_domain}_bruteforce"
            # Reuse output helper (treat brute results analogous to enumeration without source_map/stats)
            # Build minimal structures to satisfy helper signature
            source_map = {}
            stats = []
            _write_enum_output(output, primary_domain, brute_results, source_map, stats, status_map=status_map if (args.status_code or args.live or args.match_code) else None, live_list=live_brute if (args.live or args.match_code) else None)
            fmt_disp = 'jsonl' if (getattr(args, 'json_lines', False) or args.report_format=='jsonl') else args.report_format
            log(f"\n[*] Saved to {output}.{fmt_disp}", "ok")
            return
        except KeyboardInterrupt:
            log("\n[!] Stopped by user", "warn")
            return

    # Directory brute-force
    if args.dir_bruteforce:
        log("[*] Directory Bruteforce Mode (CTRL+C to stop)")
        try:
            # Directory brute now uses -w directly
            wordlist = args.wordlist or "wordlists/directories.txt"
            ok_d, err = ensure_file(wordlist, "directory wordlist")
            if not ok_d:
                log(f"[!] {err}", "error")
                return
            exts = [e.strip() for e in args.dir_extensions.split(',')] if args.dir_extensions else []
            status_codes = [s.strip() for s in args.dir_status.split(',')] if args.dir_status else None
            base = args.targets[0] if args.targets else None
            
            # Parse match_codes for filtering display
            match_codes = None
            if args.match_code:
                match_codes = [c.strip() for c in args.match_code.split(',') if c.strip()]
                log(f"[*] Filtering display by status codes: {', '.join(sorted(match_codes))}", "info")
            
            if args.recursion:
                depth = max(1, min(5, args.rec_depth))
                results = recursive_dir_bruteforce(base, wordlist_path=wordlist, extensions=exts, threads=args.threads, timeout=args.dir_timeout, status_codes=status_codes, session=session, head_first=not args.no_head, rate_limit=args.rate_limit, max_depth=depth, match_codes=match_codes)
            else:
                results = dir_bruteforce(base, wordlist_path=wordlist, extensions=exts, threads=args.threads, timeout=args.dir_timeout, status_codes=status_codes, session=session, head_first=not args.no_head, rate_limit=args.rate_limit, match_codes=match_codes)
            
            # Apply match code filtering to final results for file output
            if args.match_code and results:
                match_codes_set = {c.strip() for c in args.match_code.split(',') if c.strip()}
                filtered_results = [r for r in results if str(r['status']) in match_codes_set]
                log(f"[*] Saving {len(filtered_results)} / {len(results)} results matching codes: {', '.join(sorted(match_codes_set))}", "info")
                results = filtered_results
            
            log(f"\n[OK] Directory brute-force complete. Found {len(results)} paths.", "ok")
            
            # Auto-save directory results in results folder
            results_dir = _ensure_results_dir()
            
            output_file = args.output or "directory_bruteforce"
            output_filename = os.path.basename(output_file)
            out = os.path.join(results_dir, output_filename) + (".json" if args.report_format == 'json' else '.txt')
            
            if args.report_format == 'json':
                with open(out, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                with open(out, 'w') as f:
                    for r in results:
                        f.write(f"{r['status']} {r['url']} len={r['length']}{' -> '+r['redirect'] if r['redirect'] else ''}\n")
            log(f"[*] Saved directory results to {out}", "ok")
        except KeyboardInterrupt:
            log("\n[!] Stopped by user", "warn")

    # Standalone probe mode (if no core mode but probing flags present)
    probe_mode = False
    if (args.status_code or args.live or args.raw_request_file or args.match_code) and not core_mode_selected:
        probe_mode = True

    def load_hosts_from_file(path):
        hosts = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    hosts.append(line)
        except FileNotFoundError:
            log(f"[!] Host list file not found: {path}", "error")
        except Exception as e:
            log(f"[!] Error reading host list: {e}", "error")
        return hosts

    def parse_raw_request(path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                raw = f.read().replace('\r\n', '\n')
            if '\n\n' in raw:
                head, body = raw.split('\n\n', 1)
            else:
                head, body = raw, ''
            lines = [l for l in head.split('\n') if l.strip()]
            if not lines:
                return None
            req_line = lines[0]
            parts = req_line.split()
            if len(parts) < 2:
                return None
            method = parts[0].upper()
            path_part = parts[1]
            headers = {}
            for hline in lines[1:]:
                if ':' in hline:
                    k, v = hline.split(':', 1)
                    headers[k.strip()] = v.strip()
            return {"method": method, "path": path_part, "headers": headers, "body": body}
        except Exception as e:
            log(f"[!] Failed to parse raw request: {e}", "error")
            return None

    def replay_request(hosts, raw_req, timeout=5, threads=30):
        results = {}
        if not hosts:
            return results
        method = raw_req['method']; base_path = raw_req['path']; base_headers = raw_req['headers']; body = raw_req['body']
        max_threads = min(threads, 60)

        def do_one(h):
            # ensure host without scheme
            target = h
            scheme_supplied = target.startswith('http://') or target.startswith('https://')
            schemes = ['https://', 'http://'] if not scheme_supplied else ['']
            for sch in schemes:
                url = target if scheme_supplied else sch + target + (base_path if base_path.startswith('/') else '/' + base_path)
                hds = dict(base_headers)
                # overwrite Host header
                host_only = target.replace('http://', '').replace('https://', '').split('/', 1)[0]
                hds['Host'] = host_only
                try:
                    if method in ('GET','HEAD','DELETE','OPTIONS'):
                        r = requests.request(method, url, headers=hds, timeout=timeout, allow_redirects=True)
                    else:
                        r = requests.request(method, url, headers=hds, data=body.encode() if body else None, timeout=timeout, allow_redirects=True)
                    return h, (url, r.status_code)
                except Exception:
                    continue
            return h, (None, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
            for host, data in ex.map(do_one, hosts):
                results[host] = {"url": data[0], "status": data[1]}
        return results

    # Execute probe mode if requested
    if probe_mode:
        host_inputs = []
        if args.targets:
            host_inputs.extend(args.targets)
        if args.host_list_file:
            host_inputs.extend(load_hosts_from_file(args.host_list_file))
        # Deduplicate preserving order
        seen = set(); probe_hosts = []
        for h in host_inputs:
            base = h.strip()
            if not base or base in seen:
                continue
            seen.add(base); probe_hosts.append(base)
        if not probe_hosts:
            log("[!] No hosts to probe", "error"); return
        log(f"[*] Probing {len(probe_hosts)} host(s)")
        match_codes = None
        if args.match_code:
            match_codes = {c.strip() for c in args.match_code.split(',') if c.strip()}
        raw_req = parse_raw_request(args.raw_request_file) if args.raw_request_file else None
        if raw_req:
            probe_res = replay_request(probe_hosts, raw_req, timeout=5, threads=args.threads)
        else:
            # Use existing probe_status (defaults to HEAD->GET)
            probe_res = probe_status(probe_hosts, threads=args.threads)
        live_filtered = []
        for host, meta in probe_res.items():
            if isinstance(meta, dict):
                status = meta.get('status')
                scheme = meta.get('scheme')
            else:
                status = None
                scheme = None
            
            # Build URL
            if scheme and status:
                url = f"{scheme}://{host}"
            else:
                url = host
            
            # Skip if no status (host is down)
            if status is None:
                continue
            
            # Filter by status codes if -mc specified
            if match_codes and str(status) not in match_codes:
                continue
            
            live_filtered.append({"host": host, "status": status, "url": url})
        for idx, item in enumerate(sorted(live_filtered, key=lambda x: x['host']), 1):
            log(f"{idx}. {item['status']} {item['url']}", "result")
        log(f"\n[OK] Live matched hosts: {len(live_filtered)} / {len(probe_hosts)}", "summary")
        
        # Auto-save live results to .txt in results folder
        if live_filtered:
            results_dir = _ensure_results_dir()
            
            output_file = args.output or "live_hosts"
            output_filename = os.path.basename(output_file)
            if not output_filename.endswith('.txt'):
                output_filename = f"{output_filename}.txt"
            
            output_path = os.path.join(results_dir, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                for item in sorted(live_filtered, key=lambda x: x['host']):
                    f.write(f"{item['status']} {item['url']}\n")
            log(f"[*] Saved live hosts to {output_path}", "ok")
        
        return

    # Final summary (if any mode ran)
    elapsed = time.time() - start_epoch
    if any([args.subdomain_enum, args.subdomain_bruteforce, args.dir_bruteforce]):
        modes_list = [m for m, cond in [
            ("enum", args.subdomain_enum),
            ("sub-brute-root", args.subdomain_bruteforce),
            ("dir", args.dir_bruteforce)
        ] if cond]
        log(f"\nSummary: target={primary_domain} elapsed={elapsed:.2f}s modes=" + ",".join(modes_list) +
            f" counts: enum={len(enum_results)} root-brute={len(brute_results)}", "summary")


if __name__ == "__main__":
    try:
        rc = main()
        if rc is None:
            rc = 0
        
        # Check if graceful shutdown was requested
        if _shutdown_requested and not _force_quit:
            print("\n[✓] Process stopped gracefully")
            sys.exit(130)
        
        sys.exit(rc)
    except KeyboardInterrupt:
        # Clean exit on Ctrl+C
        if not _shutdown_requested:
            print("\n[✓] Process stopped")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unhandled fatal error: {e.__class__.__name__}: {e}")
        sys.exit(1)
