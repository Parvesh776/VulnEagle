======================================
         VulnEagle - README
======================================

VulnEagle is a Python-based Command Line Interface (CLI) tool for 
web application reconnaissance and penetration testing. It is designed 
to automate the process of discovering JavaScript endpoints, fuzzing 
those endpoints, and mapping any potential vulnerabilities in the 
target web application.
VulnEagle is an automated, modular, and customizable tool that provides all the essential features needed for web application security testing. It can make your security testing workflow more efficient and effective.



======================================
Installation
======================================

1. Clone the repository:<br>
   git clone https://github.com/Parvesh776/VulnEagle.git
   cd VulnEagle

2. Install Python Dependencies
Make sure Python 3.10+ is installed. Then install required packages: <br>
--sudo apt update<br>
--sudo apt install python3-pip -y<br>
--pip3 install -r requirements.txt

3. Install Playwright (for Smart Recon module)<br>
   pip install playwright<br>
   playwright install<br>

4. Run VulnEagle<br>
   python vulneagle.py --url <target_url> [options] <br>



✅ Notes

No need to create a virtual environment. This setup works directly with system Python.
Make sure pip is updated: python -m pip install --upgrade pip
If facing permission issues, try prepending sudo (not recommended unless necessary).


======================================
Usage
======================================

Run the VulnEagle CLI tool with the following command:<br>

   | usage: vulneagle.py --url URL [options]<br>

VulnEagle 🦅 - Phishing & Vulnerability Scanner<br>

optional arguments:<br>
  -h, --help                  Show this help message and exit<br>

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
  python vulneagle.py --url https://target.com --map-inputs --auth "Bearer eyJ..." --output map.html
  python vulneagle.py --url https://target.com --fuzz --waf --output fuzz.html
  python vulneagle.py --url https://target.com --smart-recon --map-inputs --fuzz --auth "Cookie: sessionid=abc" --waf --output full.html

Project: VulnEagle | Author: @parvesh776

======================================
Contributing
======================================

If you want to contribute to VulnEagle, please fork the repository and create a pull request with your improvements.

To report bugs or request features, please use the GitHub Issues section.

======================================
License
======================================

VulnEagle is open-source software licensed under the MIT License.
