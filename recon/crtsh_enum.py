# recon/crtsh_enum.py
import requests

def fetch_subdomains(domain):
    print(f"[🔍] Gathering subdomains for: {domain}")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []

        data = resp.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())

        print(f"[✔] Found {len(subdomains)} subdomains.")
        return list(subdomains)

    except Exception as e:
        print(f"[!] Failed to fetch subdomains: {e}")
        return []
