import requests

def detect_waf(url):
    try:
        response = requests.get(url, timeout=5)
        server = response.headers.get('Server', '').lower()
        waf_signatures = {
            'cloudflare': 'Cloudflare',
            'akamai': 'Akamai',
            'sucuri': 'Sucuri',
            'imperva': 'Imperva',
            'f5': 'F5 BIG-IP',
            'barracuda': 'Barracuda',
            'aws': 'AWS WAF',
        }
        for sig, name in waf_signatures.items():
            if sig in server:
                return name
        if response.status_code == 403:
            return "Possible WAF (403 Forbidden)"
        return None
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
