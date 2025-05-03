import requests
import socket
import time

# Internal IP ranges to probe
INTERNAL_IPS = [
    "127.0.0.1",
    "169.254.169.254",  # AWS metadata
    "192.168.0.1",
    "10.0.0.1",
    "172.16.0.1"
]

COMMON_PORTS = [80, 443, 22, 3306, 8080, 5000]

AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def check_ssrf_vulnerability(target_url, session=None):
    print("[+] Checking for potential SSRF vulnerabilities...")
    vulnerable = False
    headers = {"User-Agent": "VulnEagle-Scanner"}

    for ip in INTERNAL_IPS:
        probe_url = f"{target_url}?url=http://{ip}/"
        try:
            response = (session or requests).get(probe_url, headers=headers, timeout=5)
            if "EC2" in response.text or "meta-data" in response.text or response.status_code in [200, 302]:
                print(f"[!] Possible SSRF via URL: {probe_url}")
                vulnerable = True
        except Exception:
            pass

    return vulnerable


def check_aws_metadata_exposure():
    print("[+] Checking AWS metadata exposure...")
    try:
        res = requests.get(AWS_METADATA_URL, timeout=3)
        if res.status_code == 200 and "instance-id" in res.text.lower():
            print("[!] AWS Metadata exposed!")
            return True
    except Exception:
        pass
    return False


def scan_internal_ports(ip):
    print(f"[*] Scanning internal IP: {ip} for open ports...")
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            open_ports.append(port)
            sock.close()
        except Exception:
            continue
    return open_ports


def run_ssrf_module(target_url, session=None):
    results = {
        "ssrf": check_ssrf_vulnerability(target_url, session),
        "aws_metadata": check_aws_metadata_exposure(),
        "internal_ports": {}
    }

    for ip in INTERNAL_IPS:
        ports = scan_internal_ports(ip)
        if ports:
            results["internal_ports"][ip] = ports

    return results
