import os
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse
from threading import Lock
import time

_output_lock = Lock()

DEFAULT_STATUS = {200,204,301,302,307,401,403}

def _normalize_base(url: str) -> str:
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    return url.rstrip('/') + '/'

def _load_wordlist(path: str):
    try:
        with open(path,'r',encoding='utf-8',errors='ignore') as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Directory wordlist not found: {path}")
        return []
    except Exception as e:
        print(f"[!] Error reading directory wordlist: {e}")
        return []

def dir_bruteforce(base_url: str, wordlist_path: str, extensions=None, threads=30, timeout=5, status_codes=None, session=None, head_first=True, rate_limit=None, match_codes=None):
    """
    Brute force directories/files on a target web root.

    Args:
        base_url: Base target (with or without scheme)
        wordlist_path: Path to wordlist containing directory/file names
        extensions: list of extensions (e.g. ['php','bak']) or None
        threads: concurrency level
        timeout: request timeout
        status_codes: set/list of status codes to treat as 'found'
        session: optional requests-like session
        match_codes: set/list of status codes to filter output display (-mc flag)
    Returns:
        list of result dicts: {url,status,length,redirect}
    """
    base = _normalize_base(base_url)
    words = _load_wordlist(wordlist_path)
    if not words:
        return []
    extensions = [e.strip().lstrip('.') for e in (extensions or []) if e.strip()]
    if status_codes is None:
        status_codes = DEFAULT_STATUS
    else:
        status_codes = {int(s) for s in status_codes}
    
    # Convert match_codes to set if provided
    if match_codes:
        match_codes = {int(c) for c in match_codes}

    candidates = []
    for w in words:
        candidates.append(w)
        if extensions:
            for ext in extensions:
                candidates.append(f"{w}.{ext}")

    results = []

    def probe(path_fragment):
        url = urljoin(base, path_fragment)
        throttled = False
        if rate_limit:
            # simple token bucket: sleep based on global rate per second
            sleep_for = 1.0 / max(rate_limit, 1)
            time.sleep(sleep_for)
            throttled = True
        try:
            # Determine request adapter; support custom SessionHandler which lacks head()
            req = session if session else requests
            underlying_session = None
            if session is not None and not hasattr(session, 'head'):
                # Try to discover wrapped requests.Session for head() support
                underlying_session = getattr(session, 'session', None)
            response = None
            if head_first:
                try:
                    if hasattr(req, 'head'):
                        response = req.head(url, timeout=timeout, allow_redirects=False)
                    elif underlying_session is not None and hasattr(underlying_session, 'head'):
                        response = underlying_session.head(url, timeout=timeout, allow_redirects=False)
                except requests.RequestException:
                    response = None
            if response is None:
                response = req.get(url, timeout=timeout, allow_redirects=False, stream=True)
            status = response.status_code
            if status in status_codes:
                # attempt content length without reading body
                length = int(response.headers.get('Content-Length', '0')) if 'Content-Length' in response.headers else 0
                if length == 0:
                    # fallback minimal read (avoid full body)
                    try:
                        chunk = next(response.iter_content(chunk_size=256))
                        length = len(chunk)
                    except Exception:
                        length = 0
                location = response.headers.get('Location')
                
                # Only print if match_codes is None OR status is in match_codes
                should_display = (match_codes is None) or (status in match_codes)
                
                if should_display:
                    with _output_lock:
                        print(f"[+] {status} {url} (len={length}{' -> '+location if location else ''}{' throttled' if throttled else ''})")
                
                results.append({
                    'url': url,
                    'status': status,
                    'length': length,
                    'redirect': location
                })
        except requests.RequestException:
            pass

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(probe, candidates))
    except KeyboardInterrupt:
        print("\n[!] Directory bruteforce interrupted by user (CTRL+C)")
        print(f"[i] Found {len(results)} paths before interruption")
        raise

    # Attach depth=1 for uniformity with recursive output
    for r in results:
        if 'depth' not in r:
            r['depth'] = 1
    return results


def recursive_dir_bruteforce(base_url: str, wordlist_path: str, extensions=None, threads=30, timeout=5,
                             status_codes=None, session=None, head_first=True, rate_limit=None,
                             max_depth: int = 1, max_dirs: int = 200, match_codes=None):
    """Recursively brute force directories up to a depth.

    Strategy:
      - Run dir_bruteforce at current level.
      - Identify candidate directories among findings (heuristic: last segment has no '.' and status in DEFAULT_STATUS).
      - Queue those directories (dedup) until max_depth reached.
      - Propagate depth in each result dict via 'depth' key.

    Safeguards:
      - max_depth clamped 1..5
      - max_dirs limits total distinct directories queued to avoid explosion.
      - match_codes: filter display output by status codes (-mc flag)
    """
    max_depth = max(1, min(5, int(max_depth or 1)))
    all_results = []
    seen_dirs = set()
    queue = [(base_url, 1)]
    while queue:
        current_base, depth = queue.pop(0)
        level_results = dir_bruteforce(current_base, wordlist_path, extensions=extensions, threads=threads,
                                       timeout=timeout, status_codes=status_codes, session=session,
                                       head_first=head_first, rate_limit=rate_limit, match_codes=match_codes)
        for r in level_results:
            r['depth'] = depth
        all_results.extend(level_results)
        if depth >= max_depth:
            continue
        # Identify directories to recurse into
        for r in level_results:
            try:
                parsed = urlparse(r['url'])
                seg = parsed.path.rsplit('/', 1)[-1]
                if '.' in seg and seg != '':
                    continue  # treat as file
                new_path = parsed.path
                if not new_path.endswith('/'):
                    if r.get('redirect') and r['redirect'] and r['redirect'].endswith('/'):
                        new_path = r['redirect'] if r['redirect'].startswith('/') else '/' + r['redirect']
                    else:
                        new_path = new_path + '/'
                new_base = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                if new_base.lower() in seen_dirs:
                    continue
                if len(seen_dirs) >= max_dirs:
                    break
                if new_base.rstrip('/') == _normalize_base(base_url).rstrip('/'):
                    continue
                seen_dirs.add(new_base.lower())
                queue.append((new_base, depth + 1))
            except Exception:
                continue
        if len(seen_dirs) >= max_dirs:
            break
    return all_results

if __name__ == "__main__":
    # Simple self-test (won't run heavy)
    test = dir_bruteforce('http://example.com', wordlist_path=os.path.join(os.path.dirname(__file__),'..','wordlists','directories.txt'))
    print(f"Found {len(test)} paths")
