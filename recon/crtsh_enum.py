# recon/crtsh_enum.py
import requests
import os
import re
import time
import random
import json
import signal
import sys
import concurrent.futures
from pathlib import Path
from typing import Set, Optional, Dict, Callable, List, Tuple, Union
from urllib.parse import urlparse

# Disable SSL warnings for APIs with cert issues
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global flag for interrupt handling
_interrupted = False

def _signal_handler(signum, frame):
    """Handle CTRL+C: set interrupted flag for graceful stop."""
    global _interrupted
    _interrupted = True
    print("\n[!] Stopping - please wait for cleanup...")
    # Don't call sys.exit() here - let the program handle it gracefully

# Type alias for complex return (list alone, list+stats, list+stats+map, or list+map)
FetchReturn = Union[
    List[str],
    Tuple[List[str], List[Tuple[str, int, int]]],
    Tuple[List[str], List[Tuple[str, int, int]], Dict[str, Set[str]]],
    Tuple[List[str], Dict[str, Set[str]]]
]

## Removed legacy TLS toggle & timeout constant (not used by current code)

# Make PyYAML optional so the tool still works (crt.sh enumeration) even if not installed.
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None

def load_provider_config():
    """Load API keys from provider-config.yaml if PyYAML is available.

    Returns empty dict gracefully when yaml isn't installed or file invalid.
    """
    if yaml is None:
        return {}
    config_path = Path(__file__).parent / "provider-config.yaml"
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw = yaml.safe_load(f) or {}
                # Normalize: empty lists -> [], blank strings -> '', remove obviously empty tokens
                norm = {}
                for k, v in raw.items():
                    if v is None:
                        continue
                    if isinstance(v, list):
                        clean = [str(t).strip() for t in v if str(t).strip()]
                        if clean:
                            norm[k] = clean
                        else:
                            # keep empty list to indicate 'no key configured' (will be skipped quietly)
                            norm[k] = []
                    elif isinstance(v, str):
                        if v.strip():
                            norm[k] = v.strip()
                        else:
                            norm[k] = ''
                    else:
                        # Keep other scalar types verbatim
                        norm[k] = v
                return norm
        except Exception as e:
            print(f"[!] Failed to load provider config: {e}")
    return {}

def fetch_from_crtsh(domain):
    """Fetch subdomains from crt.sh with retries and HTML fallback.

    crt.sh quirks handled:
      - Sometimes returns HTML (rate limits or maintenance) even with output=json
      - Duplicate entries / wildcard names
      - Newline-separated multi-name entries in JSON

    Strategy:
      1. Try JSON endpoint up to 3 times with small backoff.
      2. If JSON decode fails, fall back to HTML parsing (regex for domain matches).
      3. Normalize, dedupe, and filter wildcard prefixes.
    """
    base_url = "https://crt.sh/"
    query_url = f"{base_url}?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; VulnEagle/1.0; +https://github.com/)"
    }
    subdomains: set[str] = set()

    # Retry JSON attempts
    for attempt in range(3):
        try:
            resp = requests.get(query_url, headers=headers, timeout=30)
            if resp.status_code != 200:
                time.sleep(1 + attempt * 0.5)
                continue
            try:
                data = resp.json()
            except Exception:
                # Possibly HTML or truncated; break to fallback
                data = None
            if data is None:
                break
            for entry in data:
                name_value = entry.get("name_value", "")
                for raw in name_value.split('\n'):
                    s = raw.strip().lower()
                    if not s:
                        continue
                    if s.startswith('*.'):
                        # include non-wildcard version if pattern like *.sub.domain
                        plain = s.lstrip('*.')
                        if plain.endswith(domain):
                            subdomains.add(plain)
                        continue
                    if s.endswith(domain):
                        subdomains.add(s)
            # Success path
            return subdomains
        except requests.RequestException:
            time.sleep(0.5 + attempt * 0.5)
        except Exception:
            break

    # HTML fallback parsing
    try:
        fallback_url = f"{base_url}?q=%25.{domain}"
        resp = requests.get(fallback_url, headers=headers, timeout=30)
        if resp.status_code == 200:
            # Find domain-like tokens; exclude leading wildcard
            pattern = re.compile(rf"([A-Za-z0-9_\-\.]+\.{re.escape(domain)})")
            for match in pattern.finditer(resp.text):
                s = match.group(1).lower()
                if s.startswith('*.'):
                    s = s[2:]
                if s.endswith(domain):
                    subdomains.add(s)
    except Exception as e:
        print(f"[!] crt.sh fallback error: {e}")

    return subdomains

def fetch_from_bevigil(domain, api_key):
    """Fetch subdomains from BeVigil (OSINT API)"""
    if not api_key:
        return set()
    try:
        headers = {"X-Access-Token": api_key}
        url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data.get("subdomains", []) or []:
                if s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception as e:
        print(f"[!] BeVigil error: {e}")
    return set()

def fetch_from_builtwith(domain, api_key):
    """Fetch from BuiltWith API"""
    if not api_key:
        return set()
    try:
        url = f"https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP={domain}"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            subs.add(domain)
            # BuiltWith returns tech stack, not subdomains directly
            # Extract from URLs if present
            for result in data.get("Results", []) or []:
                for path in result.get("Paths", []) or []:
                    url_str = path.get("Url", "")
                    if "://" in url_str:
                        host = url_str.split("://")[1].split("/")[0].lower()
                        if host.endswith(domain):
                            subs.add(host)
            return subs
    except Exception as e:
        print(f"[!] BuiltWith error: {e}")
    return set()

def fetch_from_chinaz(domain, api_key):
    """Fetch from Chinaz subdomain API"""
    if not api_key:
        return set()
    try:
        url = f"https://apidatav2.chinaz.com/CallAPI/Alexa?key={api_key}&domainName={domain}"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            # Chinaz structure varies; adapt as needed
            for item in data.get("Result", {}).get("SubDomainList", []) or []:
                s = item.get("SubDomain")
                if s and s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_from_dnsdb(domain, api_key):
    """Fetch from DNSDB (Farsight Security)"""
    if not api_key:
        return set()
    try:
        headers = {"X-API-Key": api_key, "Accept": "application/json"}
        url = f"https://api.dnsdb.info/lookup/rrset/name/*.{domain}"
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            subs = set()
            for line in resp.text.strip().split('\n'):
                try:
                    obj = json.loads(line) if line.strip() else {}
                    rrname = obj.get("rrname", "")
                    if rrname.endswith(domain):
                        subs.add(rrname.lower().rstrip('.'))
                except:
                    pass
            return subs
    except Exception as e:
        print(f"[!] DNSDB error: {e}")
    return set()

def fetch_from_dnsrepo(domain, api_key):
    """Fetch from DNSRepo API"""
    if not api_key:
        return set()
    try:
        url = f"https://dnsrepo.noc.org/api/?apikey={api_key}&domain={domain}&search=subdomains"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for item in data.get("subdomains", []) or []:
                if isinstance(item, str) and item.endswith(domain):
                    subs.add(item.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_from_fofa(domain, api_key):
    """Fetch from FOFA (Cyberspace Search Engine)"""
    if not api_key:
        return set()
    try:
        import base64
        # FOFA needs email:key format or just key
        if ":" in api_key:
            email, key = api_key.split(":", 1)
        else:
            email, key = "", api_key
        
        query = f'domain="{domain}"'
        query_b64 = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={query_b64}&size=100"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for result in data.get("results", []) or []:
                if result and len(result) > 0:
                    host = result[0]
                    if isinstance(host, str) and host.endswith(domain):
                        subs.add(host.lower())
            return subs
    except Exception as e:
        print(f"[!] FOFA error: {e}")
    return set()

def fetch_from_github(domain, api_key):
    """Fetch from GitHub Code Search (finds subdomains in code)"""
    if not api_key:
        return set()
    try:
        headers = {"Authorization": f"token {api_key}", "Accept": "application/vnd.github+json"}
        query = f'"{domain}" in:file'
        url = f"https://api.github.com/search/code?q={query}&per_page=100"
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            pattern = re.compile(rf"([a-z0-9_\-\.]+\.{re.escape(domain)})", re.IGNORECASE)
            for item in data.get("items", []) or []:
                # Note: actual file content not returned in search; would need to fetch file
                # Extract from name/path if present
                text = str(item.get("name", "")) + str(item.get("path", ""))
                for match in pattern.finditer(text):
                    s = match.group(1).lower()
                    if not s.startswith("*."):
                        subs.add(s)
            return subs
    except Exception as e:
        print(f"[!] GitHub error: {e}")
    return set()

def fetch_from_intelx(domain, api_key):
    """Fetch from Intelligence X (fast mode)"""
    if not api_key:
        return set()
    try:
        headers = {"x-key": api_key, "Content-Type": "application/json"}
        # Start search with reduced timeout
        search_data = {"term": domain, "buckets": [], "lookuplevel": 0, "maxresults": 50, "timeout": 0, "datefrom": "", "dateto": "", "sort": 2, "media": 0, "terminate": []}
        resp = requests.post("https://2.intelx.io/phonebook/search", headers=headers, json=search_data, timeout=10)
        if resp.status_code == 200:
            search_result = resp.json()
            search_id = search_result.get("id")
            if not search_id:
                return set()
            
            # Get results quickly
            time.sleep(0.5)  # Reduced wait
            result_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=50"
            resp2 = requests.get(result_url, headers=headers, timeout=10)
            if resp2.status_code == 200:
                results = resp2.json()
                subs = set()
                for item in results.get("selectors", []) or []:
                    selector = item.get("selectorvalue", "")
                    if selector.endswith(domain):
                        subs.add(selector.lower())
                return subs
    except Exception:
        # Silent fail for speed
        pass
    return set()

def fetch_from_quake(domain, api_key):
    """Fetch from Quake (360 Cyberspace Search)"""
    if not api_key:
        return set()
    try:
        headers = {"X-QuakeToken": api_key, "Content-Type": "application/json"}
        data = {"query": f'domain:"{domain}"', "start": 0, "size": 100}
        resp = requests.post("https://quake.360.cn/api/v3/search/quake_service", headers=headers, json=data, timeout=12)
        if resp.status_code == 200:
            result = resp.json()
            subs = set()
            for item in result.get("data", []) or []:
                service = item.get("service", {})
                host = service.get("http", {}).get("host") or item.get("domain")
                if host and host.endswith(domain):
                    subs.add(host.lower())
            return subs
    except Exception:
        pass  # Silent fail for speed
    return set()

def fetch_from_threatbook(domain, api_key):
    """Fetch from ThreatBook (微步在线)"""
    if not api_key:
        return set()
    try:
        url = f"https://api.threatbook.cn/v3/domain/sub_domains"
        params = {"apikey": api_key, "resource": domain}
        resp = requests.get(url, params=params, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data.get("data", {}).get("sub_domains", []) or []:
                if s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception:
        pass  # Silent fail for speed
    return set()

def fetch_from_zoomeye(domain, api_key):
    """Fetch from ZoomEye"""
    if not api_key:
        return set()
    try:
        headers = {"API-KEY": api_key}
        url = f"https://api.zoomeye.org/domain/search?q={domain}&type=0&page=1"
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for item in data.get("list", []) or []:
                name = item.get("name")
                if name and name.endswith(domain):
                    subs.add(name.lower())
            return subs
    except Exception as e:
        print(f"[!] ZoomEye error: {e}")
    return set()

def fetch_from_virustotal(domain, api_key):
    """Fetch subdomains from VirusTotal API with effectively unlimited pagination.

    Changes:
      - Removed previous static max_pages=10 cap.
      - Optional env override: VE_VIRUSTOTAL_MAX_PAGES (int) to hard-limit if user wants.
      - Safety guards: loop stops if total function time > 28s (to respect outer 30s wrapper),
        if a 'next' URL repeats (cycle), or if pages exceed 2000 (sanity upper bound when unlimited).
    """
    if not api_key:
        return set()
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    subs: set[str] = set()
    pages = 0
    # Read optional env-configurable page cap
    env_cap = os.getenv("VE_VIRUSTOTAL_MAX_PAGES")
    try:
        max_pages = int(env_cap) if env_cap and env_cap.isdigit() else None
    except Exception:
        max_pages = None
    start_time = time.time()
    visited_urls = set()
    try:
        while url:
            # Safety conditions
            if url in visited_urls:  # avoid cycles
                break
            visited_urls.add(url)
            if max_pages is not None and pages >= max_pages:
                break
            # Hard safety to avoid exceeding outer provider timeout (30s)
            if time.time() - start_time > 28:
                break
            if pages > 2000:  # absolute sanity cap
                break

            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code != 200:
                if resp.status_code in (429, 503):
                    time.sleep(1)  # brief backoff then retry same page
                    continue
                break
            try:
                data = resp.json()
            except Exception:
                break
            for item in data.get("data", []) or []:
                subdomain = item.get("id", "")
                if subdomain and subdomain.endswith(domain):
                    subs.add(subdomain.lower())
            next_link = data.get("links", {}).get("next") if isinstance(data.get("links"), dict) else None
            url = next_link
            pages += 1
    except Exception:
        pass  # Silent fail for speed
    return subs

def fetch_from_binaryedge(domain, api_key):
    if not api_key:
        return set()
    subs = set()
    page = 1
    max_pages = 10  # Increased for full potential
    try:
        while page <= max_pages:
            url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}"
            resp = requests.get(url, headers={"X-Key": api_key}, timeout=12)
            if resp.status_code != 200:
                if resp.status_code in (429, 503):
                    time.sleep(1 + page * 0.7)
                    continue
                break
            data = resp.json()
            arr = data.get('subdomains', [])
            if not arr:
                break
            for s in arr:
                if s:
                    subs.add(f"{s}.{domain}".lower())
            page += 1
    except Exception as e:
        print(f"[!] BinaryEdge error: {e}")
    return subs


def fetch_from_fullhunt(domain, api_key):
    if not api_key:
        return set()
    try:
        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"  # returns {"subdomains": []}
        resp = requests.get(url, headers={"X-API-KEY": api_key}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data.get('subdomains', []):
                if s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception as e:
        print(f"[!] FullHunt error: {e}")
    return set()

def fetch_from_leakix(domain, api_key):
    """Fetch from LeakIX with timeout handling"""
    if not api_key:
        return set()
    try:
        url = f"https://leakix.net/api/subdomains/{domain}?key={api_key}"
        # Quick timeout for speed
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data if isinstance(data, list) else data.get('subdomains', []):
                if isinstance(s, str) and s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except requests.exceptions.Timeout:
        # Silent fail on timeout - don't spam errors
        pass
    except Exception:
        # Silent fail on other errors
        pass
    return set()

def fetch_from_netlas(domain, api_key):
    if not api_key:
        return set()
    subs = set()
    page = 1
    max_pages = 10  # Increased for full potential
    try:
        while page <= max_pages:
            url = f"https://app.netlas.io/api/domains/{domain}/subdomains/?page={page}&limit=1000"
            resp = requests.get(url, headers={"X-API-Key": api_key}, timeout=15)
            if resp.status_code != 200:
                if resp.status_code in (429, 503):
                    time.sleep(0.5)
                    continue
                break
            data = resp.json()
            arr = data.get('items', []) or data.get('subdomains', [])
            if not arr:
                break
            for s in arr:
                if isinstance(s, str):
                    if not s.endswith(domain):
                        s = f"{s}.{domain}"
                    subs.add(s.lower())
            if len(arr) < 1000:
                break
            page += 1
    except Exception as e:
        print(f"[!] Netlas error: {e}")
    return subs

def fetch_from_passivetotal(domain, api_key):
    # RiskIQ PassiveTotal requires username + key (we only have one token in list). Skip if format mismatch.
    if not api_key:
        return set()
    # Expect api_key maybe "username:secret" pair.
    if ':' not in api_key:
        return set()
    user, secret = api_key.split(':', 1)
    try:
        url = f"https://api.riskiq.net/pt/v2/enrichment/subdomains/name/{domain}"
        resp = requests.get(url, auth=(user, secret), timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data.get('subdomains', []):
                if s:
                    subs.add(f"{s}.{domain}".lower())
            return subs
    except Exception as e:
        print(f"[!] PassiveTotal error: {e}")
    return set()

def fetch_from_whoisxml(domain, api_key):
    if not api_key:
        return set()
    try:
        url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={api_key}&domainName={domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data.get('result', {}).get('records', []):
                host = entry.get('domain') or entry.get('name') or ''
                if host and host.endswith(domain):
                    subs.add(host.lower())
            return subs
    except Exception as e:
        print(f"[!] WhoisXML error: {e}")
    return set()

def fetch_from_robtex(domain, _api_key=None):
    # Robtex public forward records; may not enumerate all subdomains but include hosts.
    try:
        url = f"https://api.robtex.com/pdns/forward/{domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            subs = set()
            data = resp.json()
            for rec in data:
                host = rec.get('rrname') or rec.get('name') or ''
                if host and host.endswith(domain):
                    subs.add(host.lower())
            return subs
    except Exception as e:
        print(f"[!] Robtex error: {e}")
    return set()


def fetch_from_jldc(domain):
    """Fetch subdomains from JLDC Anubis service"""
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data if isinstance(data, list) else []:
                if isinstance(s, str) and s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception as e:
        print(f"[!] JLDC error: {e}")
    return set()

def fetch_from_rapiddns(domain):
    """Fetch subdomains from RapidDNS (HTML parse)"""
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0 VulnEagle"})
        if resp.status_code == 200:
            # Table rows contain <td><a href="/domain/...">sub.domain</a></td>
            pattern = re.compile(rf">([A-Za-z0-9_\-\.]+\.{re.escape(domain)})<")
            subs = set(m.group(1).lower() for m in pattern.finditer(resp.text) if m.group(1).lower().endswith(domain))
            return subs
    except Exception as e:
        print(f"[!] RapidDNS error: {e}")
    return set()


def fetch_from_bufferover(domain):
    """Fetch subdomains from BufferOver (TLS + DNS endpoints)"""
    subs = set()
    try:
        # Try TLS endpoint
        url = f"https://tls.bufferover.run/dns?q=.{domain}"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0 VulnEagle"})
        if resp.status_code == 200:
            data = resp.json()
            # Results format: "subdomain,ip"
            if 'Results' in data and data['Results']:
                for item in data['Results']:
                    if isinstance(item, str):
                        parts = item.split(',')
                        if parts and parts[0].lower().endswith(domain):
                            subs.add(parts[0].lower().strip())
        
        # Try DNS endpoint as well
        url2 = f"https://dns.bufferover.run/dns?q=.{domain}"
        resp2 = requests.get(url2, timeout=15, headers={"User-Agent": "Mozilla/5.0 VulnEagle"})
        if resp2.status_code == 200:
            data2 = resp2.json()
            if 'FDNS_A' in data2 and data2['FDNS_A']:
                for item in data2['FDNS_A']:
                    if isinstance(item, str):
                        parts = item.split(',')
                        if parts and parts[0].lower().endswith(domain):
                            subs.add(parts[0].lower().strip())
    except Exception:
        pass
    return subs

def fetch_from_commoncrawl(domain):
    """Fetch subdomains from CommonCrawl index"""
    subs = set()
    try:
        # Use recent index - updated quarterly
        indexes = [
            "CC-MAIN-2024-38",  # Sept 2024
            "CC-MAIN-2024-33",  # Aug 2024
        ]
        
        for index in indexes[:1]:  # Use only latest to avoid timeout
            url = f"https://index.commoncrawl.org/{index}-index"
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'limit': 1000
            }
            try:
                resp = requests.get(url, params=params, timeout=20, headers={"User-Agent": "Mozilla/5.0 VulnEagle"})
                if resp.status_code == 200:
                    for line in resp.text.strip().split('\n'):
                        if line:
                            try:
                                data = json.loads(line)
                                if 'url' in data:
                                    parsed = urlparse(data['url'])
                                    host = parsed.netloc.lower().split(':')[0]
                                    if host.endswith(domain) and not host.startswith('*.'):
                                        subs.add(host)
                            except:
                                continue
            except:
                continue
    except Exception:
        pass
    return subs

def fetch_from_hackertarget(domain):
    """Fetch subdomains from HackerTarget hostsearch (domain,ip CSV lines)"""
    try:
        url = f"http://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200 and 'error check' not in resp.text.lower():
            subs = set()
            for line in resp.text.splitlines():
                parts = line.split(',')
                if parts:
                    host = parts[0].strip().lower()
                    if host.endswith(domain):
                        subs.add(host)
            return subs
    except Exception as e:
        print(f"[!] HackerTarget error: {e}")
    return set()

def fetch_from_wayback(domain):
    """Fetch subdomains via Wayback Machine CDX API (original URLs)."""
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            # First row is header typically when output=json; ensure list handling
            for row in data[1:] if isinstance(data, list) and len(data) > 1 else []:
                if isinstance(row, list) and row:
                    original = row[0]
                else:
                    original = row if isinstance(row, str) else ''
                original = original.lower()
                # Extract host portion
                if '://' in original:
                    original = original.split('://', 1)[1]
                host = original.split('/', 1)[0]
                if host.endswith(domain) and not host.startswith('*.'):
                    subs.add(host)
            return subs
    except Exception:
        pass
    return set()

def fetch_from_alienvault(domain):
    """Fetch subdomains from AlienVault OTX passive DNS (unauth, limited)."""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for e in data.get('passive_dns', []) if isinstance(data, dict) else []:
                host = e.get('hostname') or e.get('record') or ''
                if isinstance(host, str) and host.lower().endswith(domain):
                    subs.add(host.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_from_threatminer(domain):
    """Fetch subdomains from ThreatMiner domain API."""
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for s in data.get('results', []) if isinstance(data, dict) else []:
                if isinstance(s, str) and s.endswith(domain):
                    subs.add(s.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_from_riddler(domain, api_key=None):
    """Fetch subdomains from Riddler (requires API token if provided)."""
    if not api_key:
        return set()
    try:
        params = {"query": f"pld:{domain}", "export": "json"}
        headers = {"Authorization": f"Bearer {api_key}"}
        resp = requests.get("https://riddler.io/api/search", params=params, headers=headers, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for item in data if isinstance(data, list) else []:
                host = item.get('host') if isinstance(item, dict) else None
                if host and host.endswith(domain):
                    subs.add(host.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_from_urlscan(domain, api_key=None, aggressive=False, page_limit=3):
    """Fetch subdomains from urlscan.io search API (supports paging)."""
    subs = set()
    headers = {"API-Key": api_key} if api_key else {}
    page = 1
    max_pages = page_limit if not aggressive else max(page_limit, 6)
    try:
        while page <= max_pages:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&page={page}"
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code != 200:
                if resp.status_code in (429, 503):
                    time.sleep(1 + page * 0.5)
                    continue
                break
            data = resp.json()
            arr = data.get('results', []) if isinstance(data, dict) else []
            if not arr:
                break
            for entry in arr:
                pg = entry.get('page', {}) if isinstance(entry, dict) else {}
                host = pg.get('domain') or pg.get('url') or ''
                if isinstance(host, str) and host.endswith(domain):
                    subs.add(host.lower())
            if len(arr) < 100:
                break
            page += 1
    except Exception:
        pass
    return subs

# Placeholders for providers not yet implemented but present in config.
def _unimplemented(*args, **kwargs):
    return set()

def fetch_from_securitytrails(domain, api_key):
    """Improved SecurityTrails subdomain enumeration.

    Fixes/Enhancements:
      - Adds retry cap for 429/503 (prevents infinite same-page loop).
      - Uses 'meta.max_page' when present instead of guessing by length 100.
      - Environment override: VE_SECURITYTRAILS_MAX_PAGES to hard-limit pages.
      - Overall function time budget (~25s) to respect outer provider timeout window (30s wrapper).
      - Exponential backoff with jitter for rate limits.
      - Safe exit on unexpected schema / empty pages.
    """
    if not api_key:
        return set()
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    subs: set[str] = set()
    page = 1
    start = time.time()
    hard_time_budget = 25  # seconds (internal) so outer wrapper rarely hits timeout
    # Optional env-based page cap
    env_cap = os.getenv("VE_SECURITYTRAILS_MAX_PAGES")
    try:
        env_page_cap = int(env_cap) if env_cap and env_cap.isdigit() else None
    except Exception:
        env_page_cap = None
    max_per_page_default = 100  # typical page size
    max_retries_per_page = 6
    consecutive_errors = 0
    session = requests.Session()
    try:
        while True:
            if env_page_cap and page > env_page_cap:
                break
            if time.time() - start > hard_time_budget:
                break
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?page={page}&include_inactive=true&children_only=false"
            retries = 0
            while True:
                if time.time() - start > hard_time_budget:
                    break
                try:
                    resp = session.get(url, headers=headers, timeout=(4, 7))
                except requests.exceptions.Timeout:
                    retries += 1
                    if retries >= max_retries_per_page:
                        break
                    time.sleep(0.4 * retries)
                    continue
                except Exception:
                    retries += 1
                    if retries >= max_retries_per_page:
                        break
                    time.sleep(0.3)
                    continue

                code = resp.status_code
                if code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        consecutive_errors += 1
                        break
                    arr = data.get("subdomains") or []
                    if not isinstance(arr, list):
                        # Malformed -> stop to avoid loop
                        consecutive_errors += 1
                        break
                    if not arr:
                        # No more results
                        break
                    for sub in arr:
                        if isinstance(sub, str) and sub:
                            full = f"{sub}.{domain}".lower()
                            if full.endswith(domain):
                                subs.add(full)
                    meta = data.get("meta", {}) if isinstance(data, dict) else {}
                    max_page = meta.get("max_page") or meta.get("pages") or None
                    # Advance page
                    page += 1
                    # Break inner retry loop to fetch next page
                    break
                elif code in (429, 503):
                    retries += 1
                    if retries >= max_retries_per_page:
                        # Give up on this page and overall enumeration
                        break
                    # Backoff with small jitter
                    sleep_for = min(2.0, 0.4 * (2 ** (retries - 1))) + random.uniform(0, 0.15)
                    time.sleep(sleep_for)
                    continue
                else:
                    # Non-retryable status
                    consecutive_errors += 1
                    break

            # Evaluate stop conditions after page attempt
            if env_page_cap and page > env_page_cap:
                break
            if time.time() - start > hard_time_budget:
                break
            if consecutive_errors >= 3:
                break
            # Stop if last request produced empty / failed to advance (no new subs for > 1 page)
            # meta.max_page check: if provided and we've reached beyond it -> exit
            # We captured max_page only inside success; to avoid scope confusion we re-fetch after success
            # (A tiny overhead acceptable here.)
            # If page advanced but meta said we're done, the next loop iteration will handle break when empty.
            # Continue loop otherwise.
            continue
    finally:
        try:
            session.close()
        except Exception:
            pass
    return subs

def fetch_from_shodan(domain, api_key):
    """Fetch subdomains from Shodan API"""
    if not api_key:
        return set()
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for item in data.get("subdomains", []):
                subdomains.add(f"{item}.{domain}".lower())
            return subdomains
    except Exception as e:
        print(f"[!] Shodan error: {e}")
    return set()

def fetch_from_certspotter(domain, api_key):
    """Fetch subdomains from CertSpotter API"""
    if not api_key:
        return set()
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for cert in data:
                for name in cert.get("dns_names", []):
                    name = name.lower().strip()
                    if name.endswith(domain) and not name.startswith('*'):
                        subdomains.add(name)
            return subdomains
    except Exception as e:
        print(f"[!] CertSpotter error: {e}")
    return set()

def fetch_from_chaos(domain, api_key):
    """Fetch subdomains from Chaos (ProjectDiscovery) API"""
    if not api_key:
        return set()
    try:
        headers = {"Authorization": api_key}
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for item in data.get("subdomains", []):
                subdomains.add(f"{item}.{domain}".lower())
            return subdomains
    except Exception as e:
        print(f"[!] Chaos error: {e}")
    return set()

def fetch_from_dnsdumpster(domain):
    """Fetch subdomains from DNSDumpster (free, no key)"""
    try:
        # DNSDumpster requires CSRF token from initial page
        session = requests.Session()
        url = "https://dnsdumpster.com/"
        resp = session.get(url, timeout=15)
        if resp.status_code != 200:
            return set()
        
        # Extract CSRF token
        import re
        csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)', resp.text)
        if not csrf_match:
            return set()
        csrf_token = csrf_match.group(1)
        
        # Submit form
        headers = {
            "Referer": url,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        data = {
            "csrfmiddlewaretoken": csrf_token,
            "targetip": domain,
            "user": "free"
        }
        cookies = {"csrftoken": csrf_token}
        resp = session.post(url, headers=headers, data=data, cookies=cookies, timeout=12)
        
        if resp.status_code == 200:
            # Parse HTML table for subdomains
            pattern = re.compile(rf"([a-z0-9_\-\.]+\.{re.escape(domain)})", re.IGNORECASE)
            subs = set()
            for match in pattern.finditer(resp.text):
                s = match.group(1).lower()
                if not s.startswith('*.'):
                    subs.add(s)
            return subs
    except Exception as e:
        print(f"[!] DNSDumpster error: {e}")
    return set()

def fetch_from_c99(domain, api_key):
    """Fetch subdomains from C99.nl API"""
    if not api_key:
        return set()
    try:
        url = f"https://api.c99.nl/subdomainfinder?key={api_key}&domain={domain}&json"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            if data.get("success"):
                for item in data.get("subdomains", []):
                    subdomain = item.get("subdomain") or item.get("domain")
                    if subdomain and subdomain.endswith(domain):
                        subs.add(subdomain.lower())
            return subs
    except Exception as e:
        print(f"[!] C99.nl error: {e}")
    return set()

def fetch_from_hunter(domain, api_key):
    """Fetch email domains from Hunter.io (can reveal subdomains)"""
    if not api_key:
        return set()
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            subs.add(domain)  # main domain
            # Extract from emails
            for email_obj in data.get("data", {}).get("emails", []) or []:
                email = email_obj.get("value", "")
                if "@" in email:
                    email_domain = email.split("@")[1].lower()
                    if email_domain.endswith(domain):
                        subs.add(email_domain)
            return subs
    except Exception as e:
        print(f"[!] Hunter.io error: {e}")
    return set()

def fetch_from_spyse(domain, api_key):
    """Fetch subdomains from Spyse API"""
    if not api_key:
        return set()
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"https://api.spyse.com/v4/data/domain/subdomain?domain={domain}&limit=100"
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for item in data.get("data", {}).get("items", []) or []:
                name = item.get("name")
                if name and name.endswith(domain):
                    subs.add(name.lower())
            return subs
    except Exception as e:
        print(f"[!] Spyse error: {e}")
    return set()

def fetch_from_censys(domain, api_key):
    """Fetch subdomains from Censys API (expects API_ID:SECRET format)"""
    if not api_key or ":" not in api_key:
        return set()
    api_id, secret = api_key.split(":", 1)
    try:
        url = f"https://search.censys.io/api/v2/hosts/search"
        headers = {"Content-Type": "application/json"}
        auth = (api_id, secret)
        query = f"services.tls.certificates.leaf_data.subject_dn: *{domain}"
        data = {"q": query, "per_page": 100}
        resp = requests.post(url, headers=headers, auth=auth, json=data, timeout=12)
        if resp.status_code == 200:
            result = resp.json()
            subs = set()
            for hit in result.get("result", {}).get("hits", []) or []:
                for service in hit.get("services", []) or []:
                    tls = service.get("tls", {})
                    for cert in tls.get("certificates", {}).get("leaf_data", {}).get("names", []) or []:
                        if cert.endswith(domain) and not cert.startswith("*"):
                            subs.add(cert.lower())
            return subs
    except Exception as e:
        print(f"[!] Censys error: {e}")
    return set()

def fetch_subdomains(
    domain: Optional[str],
    include: Optional[Set[str]] = None,
    exclude: Optional[Set[str]] = None,
    all_sources: bool = False,
    list_sources: bool = False,
    parallel: bool = True,
    max_workers: int = 30,
    shuffle: bool = False,
    return_stats: bool = False,
    collect_map: bool = False,
    timeout: Optional[int] = None,
    max_time: Optional[int] = None,
    recursive_only: bool = False,
) -> "FetchReturn":
    """Enhanced provider-based passive enumeration with source selection & stats.

    Parameters:
        domain: Target domain (can be None when list_sources=True)
        include: Only use these provider keys (names as in registry)
        exclude: Exclude these provider keys
        all_sources: Force use of every provider (even key-required if keys present)
        list_sources: If True, print provider list and return empty list
        shuffle: Random order execution
        return_stats: Return per-provider stats
        collect_map: Return mapping subdomain -> set(provider_labels)
        timeout: Soft per-provider time budget (seconds). Provider internal timeouts remain.
        max_time: Overall time budget (seconds) for all providers.
        recursive_only: Keep only providers flagged as recursive-capable.

    Returns:
        Depending on flags, list of subdomains OR tuple(s) with stats and/or map.
    """
    config = load_provider_config() or {}

    # Registry extended: (key, func, needs_key, label, recursive_capable)
    providers = [
        ("crtsh", fetch_from_crtsh, False, "crt.sh", True),
        ("jldc", fetch_from_jldc, False, "JLDC", True),
        ("rapiddns", fetch_from_rapiddns, False, "RapidDNS", True),
        ("bufferover", fetch_from_bufferover, False, "BufferOver", True),
        ("commoncrawl", fetch_from_commoncrawl, False, "CommonCrawl", True),
        ("wayback", fetch_from_wayback, False, "Wayback", True),
        ("alienvault", fetch_from_alienvault, False, "AlienVault", True),
        ("threatminer", fetch_from_threatminer, False, "ThreatMiner", True),
        ("hackertarget", fetch_from_hackertarget, False, "HackerTarget", True),
        ("robtex", fetch_from_robtex, False, "Robtex", True),
        ("dnsdumpster", fetch_from_dnsdumpster, False, "DNSDumpster", True),
        ("urlscan", fetch_from_urlscan, True, "UrlScan", True),
        ("riddler", fetch_from_riddler, True, "Riddler", True),
        ("virustotal", fetch_from_virustotal, True, "VirusTotal", True),
        ("securitytrails", fetch_from_securitytrails, True, "SecurityTrails", True),
        ("shodan", fetch_from_shodan, True, "Shodan", True),
        ("certspotter", fetch_from_certspotter, True, "CertSpotter", True),
        ("chaos", fetch_from_chaos, True, "Chaos (ProjectDiscovery)", True),
        ("binaryedge", fetch_from_binaryedge, True, "BinaryEdge", True),
        ("fullhunt", fetch_from_fullhunt, True, "FullHunt", True),
        ("leakix", fetch_from_leakix, True, "LeakIX", True),
        ("netlas", fetch_from_netlas, True, "Netlas", True),
        ("passivetotal", fetch_from_passivetotal, True, "PassiveTotal", True),
        ("whoisxmlapi", fetch_from_whoisxml, True, "WhoisXML", True),
        ("c99", fetch_from_c99, True, "C99.nl", True),
        ("hunter", fetch_from_hunter, True, "Hunter.io", True),
        ("spyse", fetch_from_spyse, True, "Spyse", True),
        ("censys", fetch_from_censys, True, "Censys", True),
        ("bevigil", fetch_from_bevigil, True, "BeVigil", True),
        ("builtwith", fetch_from_builtwith, True, "BuiltWith", True),
        ("chinaz", fetch_from_chinaz, True, "Chinaz", True),
        ("dnsdb", fetch_from_dnsdb, True, "DNSDB", True),
        ("dnsrepo", fetch_from_dnsrepo, True, "DNSRepo", True),
        ("fofa", fetch_from_fofa, True, "FOFA", True),
        ("github", fetch_from_github, True, "GitHub", True),
        ("intelx", fetch_from_intelx, True, "IntelX", True),
        ("quake", fetch_from_quake, True, "Quake360", True),
        ("threatbook", fetch_from_threatbook, True, "ThreatBook", True),
        ("zoomeye", fetch_from_zoomeye, True, "ZoomEye", True),
    ]

    registry_map = {p[0]: p for p in providers}

    if list_sources:
        print("Available Sources ( * = requires API key ):")
        for key, _f, needs_key, label, _r in providers:
            print(f"  {key:<15} {label}{' *' if needs_key else ''}")
        return []

    if not domain:
        return []

    def _resolve_api_key(key_name: str):
        """Resolve API key from config or environment.

        Environment precedence:
          VE_<NAME>_KEY, VE_<NAME>, <NAME>_KEY
        Falls back to first non-empty token in config (str or list).
        """
        env_candidates = [f"VE_{key_name.upper()}_KEY", f"VE_{key_name.upper()}", f"{key_name.upper()}_KEY"]
        for ev in env_candidates:
            val = os.getenv(ev)
            if val and val.strip():
                return val.strip()
        raw = config.get(key_name)
        if isinstance(raw, (list, tuple)):
            for token in raw:
                if token and str(token).strip():
                    return str(token).strip()
        elif isinstance(raw, str) and raw.strip():
            return raw.strip()
        return None

    # Source selection logic
    selected = []
    include_lower = {s.lower() for s in include} if include else None
    exclude_lower = {s.lower() for s in exclude} if exclude else set()

    for p in providers:
        key, _f, needs_key, _label, recursive_capable = p
        if include_lower and key not in include_lower:
            continue
        if key in exclude_lower:
            continue
        if recursive_only and not recursive_capable:
            continue
        # If not all_sources and provider requires key that's missing -> skip silently
        if (not all_sources) and needs_key:
            api_conf_val = config.get(key)
            # Empty list or blank string in config treated as intentionally unconfigured
            if (isinstance(api_conf_val, list) and len([t for t in api_conf_val if str(t).strip()]) == 0) or (isinstance(api_conf_val, str) and not api_conf_val.strip()):
                if not include_lower:  # allow explicit -s override to still attempt
                    continue
            if not _resolve_api_key(key):
                continue
        selected.append(p)

    if shuffle and selected:
        import random
        random.shuffle(selected)
        # Always keep crt.sh first even when shuffling (user expects it to run)
        for i, p in enumerate(selected):
            if p[0] == 'crtsh':
                # Move to front
                selected.insert(0, selected.pop(i))
                break

    print(f"[] Gathering subdomains for: {domain} (sources={len(selected)})")
    if not selected:
        print("[!] No providers selected (check keys / include/exclude options)")
        return []

    aggregate: Set[str] = set()
    per_source_counts: List[Tuple[str,int,int]] = []
    source_map: Dict[str, Set[str]] = {} if collect_map else {}

    start_all = time.time()

    def run_provider(entry):
        key, func, needs_key, label, _rec = entry
        api_key = _resolve_api_key(key) if needs_key else None
        if needs_key and not api_key:
            return label, set()
        
        # Show which API is being queried
        print(f"    [->] Querying {label}...", flush=True)
        
        started = time.time()
        subs: Set[str] = set()
        
        def call_api():
            """Inner function to call the API"""
            result_subs = set()
            try:
                if needs_key:
                    try:
                        raw_res = func(domain, api_key)
                    except TypeError:
                        raw_res = func(domain, api_key)
                else:
                    try:
                        raw_res = func(domain)
                    except TypeError:
                        raw_res = func(domain)
                if not isinstance(raw_res, (set, list, tuple)):
                    raw_res = []
                result_subs = {s.lower().strip() for s in raw_res if isinstance(s, str) and s.lower().strip().endswith(domain)}
            except Exception:
                result_subs = set()
            return result_subs
        
        # Execute with timeout using ThreadPoolExecutor
        # Special timeout handling:
        #   - crt.sh: give generous 40s (its own internal requests timeouts are 30s)
        #   - Paginated heavy APIs: 30s
        #   - Wayback: 8s (was 15s)
        #   - Others: 15s
        if label == "crt.sh":
            timeout_limit = 40
        elif label == "Wayback":
            timeout_limit = 8
        elif label in ["VirusTotal", "SecurityTrails", "Netlas", "BinaryEdge"]:
            timeout_limit = 30
        else:
            timeout_limit = 15
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(call_api)
                subs = future.result(timeout=timeout_limit)
        except concurrent.futures.TimeoutError:
            if label == "crt.sh":
                # One graceful fallback attempt without outer timeout (relies on internal 30s per request)
                print(f"    [!] crt.sh exceeded {timeout_limit}s - performing one final direct attempt...", flush=True)
                try:
                    subs = call_api()
                    print(f"    [OK] crt.sh final attempt succeeded - Found {len(subs)} subdomain(s)", flush=True)
                    return label, subs
                except Exception:
                    print("    [!] crt.sh final attempt failed", flush=True)
                    return label, set()
            elif label == "Wayback":
                print(f"    [!] Wayback provider timed out after {timeout_limit}s and was skipped.", flush=True)
                return label, set()
            else:
                print(f"    [!] {label} exceeded {timeout_limit}s limit - skipping", flush=True)
                return label, set()
        except Exception:
            subs = set()
        
        elapsed = time.time() - started
        
        # Show completion with result count
        print(f"    [OK] {label} completed in {elapsed:.1f}s - Found {len(subs)} subdomain(s)", flush=True)
        
        return label, subs

    def record(label: str, new_set: Set[str]):
        before = len(aggregate)
        aggregate.update(new_set)
        added = len(aggregate) - before
        per_source_counts.append((label, len(new_set), added))
        if collect_map and new_set:
            for s in new_set:
                source_map.setdefault(s, set()).add(label)

    # Parallel or sequential execution
    if parallel:
        import concurrent.futures
        from concurrent.futures import FIRST_COMPLETED
        heartbeat_interval = 5  # seconds between progress pulses
        last_heartbeat = time.time()
        # Removed slow-abort logic (caused premature skips and post-fallback stalls). We'll rely solely on per-provider timeouts.
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(run_provider, p): p for p in selected}
                start_times = {f: time.time() for f in futures}
                pending = set(futures.keys())
                completed = 0
                try:
                    while pending:
                        # Global time budget check
                        if max_time and (time.time() - start_all) > max_time:
                            print('[!] Max time reached; stopping further provider waits')
                            break
                        done, pending = concurrent.futures.wait(pending, timeout=heartbeat_interval, return_when=FIRST_COMPLETED)
                        if not done:
                            elapsed = time.time() - start_all
                            labels = []
                            for pf in list(pending)[:6]:
                                meta = futures.get(pf)
                                if meta:
                                    labels.append(meta[3])
                            more = '' if len(labels) == len(pending) else '…'
                            # Special message if only Wayback is left
                            if len(pending) == 1 and labels and labels[0] == "Wayback":
                                print(f"    [..] Waiting for Wayback provider (can be slow or rate-limited)... | elapsed {elapsed:.1f}s", flush=True)
                            else:
                                print(f"    [..] Waiting... {len(pending)} provider(s): {', '.join(labels)}{more} | elapsed {elapsed:.1f}s", flush=True)
                            continue
                        # Process completed futures
                        for fut in done:
                            try:
                                label, new_set = fut.result()
                            except KeyboardInterrupt:
                                raise
                            except Exception:
                                meta = futures.get(fut)
                                label = meta[3] if meta else '<unknown>'
                                new_set = set()
                            record(label, new_set)
                            completed += 1
                            remaining = len(pending)
                            if remaining and (time.time() - last_heartbeat) > heartbeat_interval:
                                print(f"    [..] Progress: {completed}/{len(futures)} providers done; {remaining} remaining", flush=True)
                                last_heartbeat = time.time()
                except KeyboardInterrupt:
                    print('\n[!] Stopping enumeration (CTRL+C pressed)...')
                    for pf in pending:
                        pf.cancel()
                    print(f'[i] Collected {len(aggregate)} subdomains before interruption')
                    raise
        except KeyboardInterrupt:
            print('[!] Enumeration stopped by user')
            raise
    else:
        try:
            for p in selected:
                if max_time and (time.time() - start_all) > max_time:
                    print("[!] Max time reached; aborting remaining providers")
                    break
                label, new_set = run_provider(p)
                record(label, new_set)
        except KeyboardInterrupt:
            print("\n[!] Enumeration interrupted by user (CTRL+C)")
            print(f"[i] Collected {len(aggregate)} subdomains before interruption")
            raise

    for label, raw_count, added in per_source_counts:
        print(f"    [+] {label}: {raw_count} (new: {added})")
    print(f"[OK] Found {len(aggregate)} unique subdomains from selected sources.")

    # Provide notice on missing keys when user likely wanted everything
    if all_sources:
        missing = []
        for key, _f, needs_key, label, _r in providers:
            if needs_key and not _resolve_api_key(key):
                missing.append(label)
        if missing:
            print(f"[i] Missing API keys for: {', '.join(missing)} | add them via provider-config.yaml or env (VE_<NAME>_KEY) for more results")

    ordered = sorted(aggregate)
    if return_stats and collect_map:
        return ordered, per_source_counts, source_map
    if return_stats:
        return ordered, per_source_counts
    if collect_map:
        return ordered, source_map  # maintain some backward compatibility
    return ordered
