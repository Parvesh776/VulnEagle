import requests
from bs4 import BeautifulSoup

def fetch_dnsdumpster_subdomains(domain):
    print(f"[+] Querying DNSdumpster for: {domain}")
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }

        # Get CSRF token
        res = session.get('https://dnsdumpster.com/', headers=headers)
        soup = BeautifulSoup(res.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

        # Submit the form with the target domain
        cookies = session.cookies.get_dict()
        data = {
            'csrfmiddlewaretoken': csrf_token,
            'targetip': domain
        }

        response = session.post('https://dnsdumpster.com/', headers={
            'User-Agent': headers['User-Agent'],
            'Referer': 'https://dnsdumpster.com/',
        }, cookies=cookies, data=data)

        if "No records found" in response.text:
            print("[!] No subdomains found via DNSdumpster.")
            return []

        # Parse subdomains from response
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find_all("table")[1]  # 2nd table has subdomains
        subdomains = set()

        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) > 0:
                subdomain = cols[0].text.strip().split(' ')[0]
                if subdomain.endswith(domain):
                    subdomains.add(subdomain)

        return list(subdomains)

    except Exception as e:
        print(f"[!] DNSdumpster error: {e}")
        return []
