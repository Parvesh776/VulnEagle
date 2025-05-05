

  <h1>VulnEagle - Web Vulnerability Scanner</h1>

  <p><strong>VulnEagle</strong> is a Python-based Command Line Interface (CLI) tool designed for web application reconnaissance and penetration testing. It automates the discovery of JavaScript endpoints, fuzzes those endpoints, and maps potential vulnerabilities in target web applications. VulnEagle is modular, customizable, and streamlines your security testing workflow.</p>

  <h2> Installation</h2>

  <ol>
    <li><strong>Clone the repository:</strong>
      <pre><code>git clone https://github.com/Parvesh776/VulnEagle.git
cd VulnEagle</code></pre>
    </li>
    <li><strong>Install Python dependencies:</strong>
      <pre><code>sudo apt update
sudo apt install python3-pip -y
pip3 install -r requirements.txt</code></pre>
    </li>
    <li><strong>Install Playwright (for Smart Recon module):</strong>
      <pre><code>pip install playwright
playwright install</code></pre>
    </li>
  </ol>

  <h3>Notes</h3>
  <ul>
    <li>No need to create a virtual environment; this setup works directly with system Python.</li>
    <li>Ensure <code>pip</code> is updated:
      <pre><code>python -m pip install --upgrade pip</code></pre>
    </li>
    <li>If facing permission issues, consider prepending <code>sudo</code> (use cautiously).</li>
  </ul>

  <h2> Usage</h2>

  <p>Run the VulnEagle CLI tool with the following command:</p>

  <pre><code>python vulneagle.py --url &lt;target_url&gt; [options]</code></pre>

  <h3>Optional Arguments:</h3>
  <ul>
    <li><code>-h</code>, <code>--help</code>: Show help message and exit.</li>
  </ul>

  <h3>Target:</h3>
  <ul>
    <li><code>--url URL</code>: Target URL to scan (required).</li>
  </ul>

  <h3>Modules:</h3>
  <ul>
    <li><code>--smart-recon</code>: Perform smart recon (JS parsing, dynamic crawling, subdomain enumeration).</li>
    <li><code>--map-inputs</code>: Map input fields, headers, cookies, and tokens for vulnerability analysis.</li>
    <li><code>--fuzz</code>: Run fuzzing engine (XSS, SQLi, LFI, SSTI) on discovered input points.</li>
    <li><code>--waf</code>: Enable basic WAF detection and signature evasion.</li>
  </ul>

  <h3>Authentication:</h3>
  <ul>
    <li><code>--auth AUTH</code>: Provide authentication header (e.g., "Bearer &lt;token&gt;", "Cookie: sessionid=abc").</li>
    <li><code>--header HEADER</code>: Custom headers (e.g., "X-Forwarded-For: 127.0.0.1").</li>
    <li><code>--token TOKEN</code>: JWT, API key, or session token to include.</li>
  </ul>

  <h3>Reporting:</h3>
  <ul>
    <li><code>--report-format FORMAT</code>: Report format: <code>html</code> (default), <code>json</code>, <code>txt</code>.</li>
    <li><code>--output FILE</code>: Output file for the report (e.g., <code>report.html</code>).</li>
  </ul>

  <h3>Examples:</h3>
  <pre><code>python vulneagle.py --url https://target.com --smart-recon --output recon.html
python vulneagle.py --url https://target.com --map-inputs --auth "Bearer eyJ..." --output map.html
python vulneagle.py --url https://target.com --fuzz --waf --output fuzz.html
python vulneagle.py --url https://target.com --smart-recon --map-inputs --fuzz --auth "Cookie: sessionid=abc" --waf --output full.html</code></pre>

  <h2>Contributing</h2>

  <p>If you'd like to contribute to VulnEagle:</p>
  <ol>
    <li>Fork the repository.</li>
    <li>Create a new branch for your feature or fix.</li>
    <li>Make your changes and commit them.</li>
    <li>Push your branch to your forked repository.</li>
    <li>Submit a pull request with a detailed description of your changes.</li>
  </ol>

  <p>To report bugs or request features, please use the <a href="https://github.com/Parvesh776/VulnEagle/issues">GitHub Issues</a> section.</p>

  <h2>📄 License</h2>

  <p>VulnEagle is open-source software licensed under the <a href="https://opensource.org/licenses/MIT">MIT License</a>.</p>

  <hr>

  <p><strong>Project:</strong> VulnEagle | <strong>Author:</strong> <a href="https://github.com/Parvesh776">@parvesh776</a></p>

</body>
</html>
