import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from auth.session_handler import SessionHandler

def map_inputs(url, session: SessionHandler):
    print(f"[+] Mapping inputs for: {url}")
    try:
        res = session.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        form_inputs = []

        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    form_details["inputs"].append(name)

            form_inputs.append(form_details)

        return form_inputs

    except Exception as e:
        print(f"[!] Failed to parse inputs: {e}")
        return []
    
if __name__ == "__main__":
    target = "https://example.com/login"
    session = SessionHandler()
    # session.set_cookie_auth(...) if needed

    input_map = map_inputs(target, session)

    print("\n📍 Discovered Forms + Inputs:")
    for form in input_map:
        print(f"\n[Form] Action: {form['action']} | Method: {form['method']}")
        print("Inputs:", ", ".join(form['inputs']))