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

5. CLI Usage <br>
python3 vulneagle.py -url https://example.com --recon<br>
python3 vulneagle.py -url https://example.com --fuzz --auth cookie
python3 vulneagle.py --url https://example.com --smart-recon --report-format html


✅ Notes

No need to create a virtual environment. This setup works directly with system Python.
Make sure pip is updated: python -m pip install --upgrade pip
If facing permission issues, try prepending sudo (not recommended unless necessary).


======================================
Usage
======================================

Run the VulnEagle CLI tool with the following command:

python vulneagle.py --url <target_url> [options] 
python3 vulneagle.py --url https://target.com --smart-recon --report-format html



 | Option                | Description                                      |
|-----------------------|--------------------------------------------------|
| `--url`               | Target URL to scan *(required)*                 |
| `--auth <cookies.txt>`| Load auth cookies for login-required pages       |
| `--token <token>`     | Provide a bearer/auth token                      |
| `--header <header>`   | Add a custom HTTP header                         |
| `--smart-recon`       | Enable JS, subdomain, and dynamic link recon     |
| `--report-format`     | Output format: `html`, `json`, or `txt`          |
| `--output <filename>` | Save the output to a custom file                 |

======================================
Contributing
======================================

If you want to contribute to VulnEagle, please fork the repository and create a pull request with your improvements.

To report bugs or request features, please use the GitHub Issues section.

======================================
License
======================================

VulnEagle is open-source software licensed under the MIT License.
