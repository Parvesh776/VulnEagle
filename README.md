======================================
         VulnEagle - README
======================================

VulnEagle is a Python-based Command Line Interface (CLI) tool for 
web application reconnaissance and penetration testing. It is designed 
to automate the process of discovering JavaScript endpoints, fuzzing 
those endpoints, and mapping any potential vulnerabilities in the 
target web application.

======================================
Installation
======================================

1. Clone the repository:
   git clone https://github.com/yourusername/VulnEagle.git

2. Navigate to the project directory:
   cd VulnEagle


3. Set up a virtual environment (optional but recommended):
   python -m venv .venv

4. Activate the virtual environment:
   - Windows: .\.venv\Scripts\activate
   - Linux/Mac: source .venv/bin/activate

5. Install the dependencies:
   pip install -r requirements.txt

======================================
Usage
======================================

Run the VulnEagle CLI tool with the following command:

python -m vulneagle.cli --url <target_url> [options]

Options:
  --url <target_url>     : The target URL to scan (required).
  --auth <cookie_file>   : Path to the cookie file for authentication (optional).
  --token <bearer_token> : Bearer token for authentication (optional).
  --report <html/none>   : Generate an HTML report of the scan results (optional).

Example usage:
1. Scan a website and generate an HTML report:
   python -m vulneagle.cli --url https://example.com --report html

2. Scan a website with authentication using a cookie file:
   python -m vulneagle.cli --url https://example.com --auth cookies.txt --report html

3. Scan a website with a bearer token:
   python -m vulneagle.cli --url https://example.com --token YOUR_BEARER_TOKEN --report html

======================================
Modules
======================================

1. **js_scraper**: Extracts JavaScript endpoints from the target URL.
2. **fuzz_engine**: Fuzzes the extracted endpoints with predefined payloads.
3. **vuln_mapper**: Analyzes the responses and maps any potential vulnerabilities (e.g., XSS, SQLi).
4. **html_report**: Generates an HTML report of the vulnerabilities found.
5. **session_handler**: Handles authentication and session management.

======================================
Contributing
======================================

If you want to contribute to VulnEagle, please fork the repository and create a pull request with your improvements.

To report bugs or request features, please use the GitHub Issues section.

======================================
License
======================================

VulnEagle is open-source software licensed under the MIT License.
