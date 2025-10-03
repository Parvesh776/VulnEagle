"""Subdomain brute forcer with optional dnspython dependency.

If dnspython (dns) isn't installed, the module degrades gracefully and
returns an empty list while informing the user instead of crashing.
"""
import concurrent.futures
from threading import Lock

try:
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dns = None  # type: ignore

print_lock = Lock()

def check_subdomain(subdomain, domain, results, resolver, timeout):
    """Check if subdomain exists via DNS lookup using provided resolver."""
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = resolver.resolve(full_domain, 'A', lifetime=timeout)
        if answers:
            with print_lock:
                print(f"[+] Found: {full_domain}")
                results.append(full_domain)
            return full_domain
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None
    return None


def bruteforce_subdomains(domain, wordlist_path, threads=50, resolvers=None, timeout=2.0):
    """
    Brute-force subdomains using a wordlist
    
    Args:
        domain: Target domain (e.g., "example.com")
        wordlist_path: Path to wordlist file
        threads: Number of concurrent threads (default: 50)
    
    Returns:
        List of discovered subdomains
    """
    if dns is None:
        print("[!] dnspython not installed. Install with: pip install dnspython")
        return []

    print(f"[*] Starting subdomain brute-force on {domain}")
    print(f"[*] Using wordlist: {wordlist_path}")
    print(f"[*] Threads: {threads}")
    if resolvers:
        print(f"[*] Custom resolvers: {', '.join(resolvers)}")
    else:
        print("[*] Using system DNS resolvers")
    print(f"[*] DNS timeout per query: {timeout}s\n")
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        return []
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")
        return []
    
    print(f"[*] Loaded {len(subdomains)} entries from wordlist\n")
    
    # Prepare resolver
    if resolvers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = resolvers
    else:
        resolver = dns.resolver.Resolver()  # system config

    # Quick test of first resolver
    try:
        _ = resolver.resolve(domain, 'A', lifetime=timeout)
    except Exception:
        if resolvers:
            print("[!] Warning: test lookup failed with provided resolvers. Continuing anyway.")

    results = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_subdomain, sub, domain, results, resolver, timeout)
                       for sub in subdomains]
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        print("\n[!] Bruteforce interrupted by user (CTRL+C)")
        print(f"[i] Found {len(results)} subdomains before interruption")
        raise

    return sorted(set(results))
