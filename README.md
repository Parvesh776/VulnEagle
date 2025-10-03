

<h1>VulnEagle</h1>
<p><strong>VulnEagle</strong> is a reconnaissance utility providing passive subdomain enumeration (37 APIs), DNS brute forcing, HTTP(S) status probing, and recursive directory brute forcing. Optimized for speed and maximum coverage.</p>

<h2>🚀 Quick Install (Kali Linux)</h2>

<p><strong>Recommended:</strong> Fully automated installation</p>

<pre><code># Clone and install (one-time setup)
git clone https://github.com/Parvesh776/VulnEagle.git
cd VulnEagle
chmod +x install.sh
sudo ./install.sh

# Installation automatically:
# ✓ Installs to /usr/share/vulneagle/
# ✓ Creates global command: vulneagle
# ✓ Cleans up cloned directory
# ✓ Returns you to parent directory

# Use from anywhere!
vulneagle -d example.com -se
vulneagle -l hosts.txt -sc -live
</code></pre>

<p>✅ <strong>What happens:</strong></p>
<ul>
  <li>Checks Python 3.10+ requirement</li>
  <li>Installs dependencies (apt + pip fallback)</li>
  <li>Copies files to <code>/usr/share/vulneagle/</code></li>
  <li>Creates executable: <code>/usr/local/bin/vulneagle</code></li>
  <li>Automatically removes cloned directory</li>
  <li>Clean installation - no clutter!</li>
</ul>

<p>📖 <strong>Full guide:</strong> <a href="INSTALL_KALI.md">INSTALL_KALI.md</a> | <strong>API Setup:</strong> <a href="API_SETUP_GUIDE.md">API_SETUP_GUIDE.md</a></p>

<h2>Installation (Other Systems)</h2>
<ol>
  <li><strong>Clone:</strong><br><pre><code>git clone https://github.com/Parvesh776/VulnEagle.git
cd VulnEagle</code></pre></li>
  <li><strong>Install deps:</strong><br><pre><code>pip install -r requirements.txt</code></pre></li>
</ol>

<h3>Manual Kali Linux Setup</h3>
<details>
<summary><strong>Show manual/development steps</strong></summary>

<h4>Check System Readiness</h4>
<pre><code># Run system check
chmod +x check-system.sh
./check-system.sh
</code></pre>

<h4>System Packages (Recommended for Kali)</h4>
<pre><code># Install via apt
sudo apt update
sudo apt install -y python3-requests python3-yaml python3-dnspython

# Or via pip (if apt packages unavailable)
pip3 install --break-system-packages requests dnspython pyyaml
</code></pre>

<h4>Development Setup (No Installation)</h4>
<pre><code># Direct execution from cloned directory
chmod +x vulneagle.py
./vulneagle.py -d example.com -se

# Or use python directly
python3 vulneagle.py -d example.com -se
</code></pre>

<h4>Uninstall VulnEagle</h4>
<pre><code># If installed via install.sh
sudo /usr/share/vulneagle/uninstall.sh

# Or use the uninstall script from repo
chmod +x uninstall.sh
sudo ./uninstall.sh
</code></pre>
</details>

<h2>✨ Features</h2>


<h3>⚡ Performance</h3>
<ul>
  <li><strong>Fast:</strong> 15-20 seconds for full 37-API enumeration</li>
  <li><strong>Smart Timeouts:</strong> Different limits for paginated vs simple APIs</li>
  <li><strong>CTRL+C Graceful Stop:</strong> Saves collected results before exit</li>
  <li><strong>Live Progress:</strong> Real-time API query status display</li>
</ul>

<h3>🎯 Additional Features</h3>
<ul>
  <li><strong>DNS Bruteforce:</strong> Multi-threaded with custom resolvers</li>
  <li><strong>Directory Bruteforce:</strong> Recursive scanning with extensions</li>
  <li><strong>Live Host Detection:</strong> HTTP/HTTPS status code probing</li>
  <li><strong>Multi-domain Support:</strong> Batch processing from file</li>
  <li><strong>Flexible Output:</strong> TXT, JSON, JSONL formats</li>
  <li><strong>Source Tracking:</strong> Know which API found each subdomain</li>
</ul>

<h3>Requirements</h3>
<ul>
  <li><strong>Python 3.10+</strong> (Kali 2023+ has 3.11 by default)</li>
  <li><strong>requests</strong> - HTTP library (required)</li>
  <li><strong>dnspython</strong> - DNS resolution (required for subdomain bruteforce)</li>
  <li><strong>pyyaml</strong> - YAML parsing (optional, for provider-config.yaml)</li>
</ul>

<p><strong>Kali Linux:</strong> All dependencies available via apt or pip</p>

<h2>Usage</h2>
<pre><code>vulneagle -d &lt;domain|https://domain&gt; [MODE FLAGS] [OPTIONS]

Quick examples:
  # Subdomain enumeration (all 37 APIs)
  vulneagle -d example.com -se
  
  # Enumeration + live host detection
  vulneagle -d example.com -se -sc -live
  
  # DNS bruteforce
  vulneagle -d example.com -sb -w wordlists/subdomains.txt --resolver-file wordlists/resolvers.txt
  
  # Directory bruteforce (recursive)
  vulneagle -d https://app.example.com -db -w wordlists/directories.txt --recursion
  
  # Multi-domain batch
  vulneagle -dL domains.txt -se -oD results/
  
  # Probe hosts from file
  vulneagle -l hosts.txt -sc -live -mc 200,302
</code></pre>

<h3>Flag Groups Overview</h3>
<p>The CLI is organized logically—start with target / mode, then refine sources, performance, filtering, and output.</p>

<details open>
<summary><strong>1. Targets & Modes</strong></summary>

<pre><code>-d,  -domain &lt;domain&gt;          Add a target domain (repeatable)
-dL, -list &lt;file&gt;              File containing multiple domains (one per line) for enumeration
-se                           Passive subdomain enumeration (37 APIs)
-sb                           DNS subdomain brute force (requires -w + --resolver-file)
-db                           Directory brute force (single host target)
-l,  -host-list &lt;file&gt;        Host list for probe/status mode (one per line)
</code></pre>
</details>

<details>
<summary><strong>2. Source Selection (Passive Enum)</strong></summary>
<pre><code>-s,  -sources &lt;names&gt;          Include only these sources (comma list or repeat flag)
-es, -exclude-sources &lt;names&gt; Exclude these sources
-all                          Use all sources (skip only missing API key deps)
-ls, -list-sources            List available sources and exit
-recursive                    Use only recursive-capable sources (placeholder; all current marked recursive)
</code></pre>
</details>

<details>
<summary><strong>3. Wordlists & Resolvers</strong></summary>
<pre><code>-w,  --wordlist &lt;file&gt;         Wordlist for -sb (subdomains) or -db (directories)
--resolver-file, -rf &lt;file&gt;    Resolver IP list (required for -sb)
--resolver-check               Pre-check resolver UDP/53 reachability (slower)
</code></pre>
</details>

<details>
<summary><strong>4. Performance / Timeouts</strong></summary>
<pre><code>-t,  --threads N               Worker threads (default 50)
-dt, --dns-timeout SEC         DNS query timeout (default 2.0)
-dto, --dir-timeout SEC        Directory request timeout (default 5.0)
--rate-limit N                 Approx req/sec cap for directory brute
--no-head                      Disable HEAD optimization (use GET only) in directory brute
--recursion                    Enable recursive directory brute force
--rec-depth N                  Recursive depth (1-5, default 2)
--rec-max-dirs N               Max queued dirs during recursion (default 200)
-dx, --dir-extensions list     Comma extensions appended (.php,.bak,...)
-ds, --dir-status list         Override success status codes for dir brute
-timeout SEC                   Soft per-provider timeout (warn if exceeded; keep results)
-max-time SEC                  Max overall passive enumeration time budget (default 600)
</code></pre>
</details>

<details>
<summary><strong>5. Filtering (Subdomains)</strong></summary>
<pre><code>-m,  -match &lt;patterns|file&gt;    Only keep subdomains containing any pattern
-f,  -filter &lt;patterns|file&gt;   Exclude subdomains containing patterns
-mc, --match-code list         Keep only HTTP status codes in list (probe/live modes)
</code></pre>
</details>

<details>
<summary><strong>6. Probing & Raw Request</strong></summary>
<pre><code>-sc, --status-code              Probe discovered (or provided) hosts for HTTP status
-live                          Only output live (reachable) hosts
-rr, --request &lt;file&gt;          Replay raw HTTP request against each host (Host header auto-set)
</code></pre>
</details>

<details>
<summary><strong>7. Output & Reporting</strong></summary>
<pre><code>-o,   --output &lt;prefix&gt;        Output file prefix (single domain)
-oD, -output-dir &lt;dir&gt;         Output directory (multi-domain -dL)
-r,  --report-format fmt       txt | json | jsonl (default txt)
-oJ, -json                     Force JSON Lines (even if -r not set)
-cs, -collect-sources          Include sources per subdomain (JSON/JSONL)
-oI, -ip                       Resolve A record and include IPs
-q,  --quiet                   Suppress progress (results + summary only)
-v,  --verbose                 Extra diagnostics
--version                      Show version and exit
</code></pre>
</details>

<details>
<summary><strong>8. Behavior Notes</strong></summary>
<ul>
  <li>Passive enumeration: runs providers in parallel by default (retries & soft timeout warnings).</li>
  <li>Soft timeout does <em>not</em> discard results—only warns.</li>
  <li>Provide API keys via <code>recon/provider-config.yaml</code> (requires <code>PyYAML</code>) to unlock premium sources.</li>
  <li><code>-match</code> / <code>-filter</code> accept comma-separated strings or file paths (one term per line).</li>
  <li><code>-ip</code> resolution is synchronous; large result sets will slow output generation.</li>
  <li>Raw request replay supports custom methods (e.g. POST), body, and headers.</li>
</ul>
</details>

<details>
<summary><strong>9. Exit Codes</strong></summary>
<pre><code>0  Success
2  Argument / validation error
130 User interrupt (CTRL+C)
1  Unhandled fatal error
</code></pre>
</details>

<details>
<summary><strong>10. Minimal Quick Start</strong></summary>
<pre><code># Fast passive enum with live probe
python vulneagle.py -d target.com -se -sc -live

# Enhanced (all sources + JSON lines + IPs + source mapping)
python vulneagle.py -d target.com -se -all -r jsonl -cs -oI -o out

# Brute & then probe only 200/302
python vulneagle.py -d target.com -sb -w wordlists/subdomains.txt --resolver-file wordlists/resolvers.txt -sc -mc 200,302 -o brute_live

# List of domains -> JSONL, collect sources
python vulneagle.py -dL domains.txt -se -r jsonl -cs -oD out_dir
</code></pre>
</details>

<h2>⚙️ Configuration</h2>

<h3>API Keys Setup</h3>

<p>VulnEagle supports <strong>37+ subdomain enumeration APIs</strong>. Most work without keys, but adding API keys unlocks premium sources for better coverage.</p>

<p>📖 <strong>Complete API Setup Guide:</strong> <a href="API_SETUP_GUIDE.md">API_SETUP_GUIDE.md</a></p>

<h4>Quick Setup</h4>

<p><strong>Method 1: Configuration File (Recommended)</strong></p>
<pre><code># After installation
sudo nano /usr/share/vulneagle/recon/provider-config.yaml

# Before installation (development)
nano recon/provider-config.yaml

# Add your keys:
virustotal: "your-virustotal-api-key"
shodan: "your-shodan-api-key"
securitytrails: "your-securitytrails-api-key"
urlscan: "your-urlscan-api-key"
chaos: "your-chaos-api-key"
# ... (see provider-config.yaml for all available APIs)
</code></pre>

<p><strong>Method 2: Environment Variables</strong></p>
<pre><code># Temporary (current session)
export VE_VIRUSTOTAL_KEY="your-key"
export VE_SHODAN_KEY="your-key"

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export VE_VIRUSTOTAL_KEY="your-key"' >> ~/.bashrc
source ~/.bashrc
</code></pre>

<h4>View Available Sources</h4>
<pre><code># List all 37 APIs
vulneagle -d example.com -ls

# Output shows:
#   Free sources (no key needed)
#   Paid sources (marked with *)
</code></pre>

<h3>Free vs Paid APIs</h3>

<p><strong>9 Free Sources (No API Key):</strong></p>
<ul>
  <li>crt.sh, JLDC, RapidDNS, Wayback Machine</li>
  <li>AlienVault, ThreatMiner, HackerTarget, Robtex, DNSDumpster</li>
</ul>

<p><strong>28 Paid APIs (Require Keys):</strong></p>
<ul>
  <li>VirusTotal, SecurityTrails, Shodan, Chaos, CertSpotter</li>
  <li>BinaryEdge, FullHunt, LeakIX, Netlas, PassiveTotal</li>
  <li>WhoisXML, UrlScan, Riddler, C99.nl, Hunter.io</li>
  <li>Spyse, Censys, BeVigil, BuiltWith, Chinaz</li>
  <li>DNSDB, DNSRepo, FOFA, GitHub, IntelX</li>
  <li>Quake360, ThreatBook, ZoomEye</li>
</ul>

<h3>Features</h3>
<ul>
  <li>Passive multi-provider subdomain enumeration (37 APIs with parallel execution)</li>
  <li>DNS brute force with custom resolvers (multi-threaded)</li>
  <li>Optional HTTP(S) status probing (HEAD → GET fallback)</li>
  <li>Directory brute forcing with optional recursive depth and extension suffixing</li>
  <li>Unified thread model: one <code>-t</code> flag controls concurrency</li>
  <li>Rate limiting and HEAD disabling toggles for throttled targets</li>
  <li>TXT, JSON, or JSONL output formats</li>
  <li>Fail-soft design: unreachable providers won't abort the run</li>
  <li>Auto-save results to files (no manual output redirection needed)</li>
</ul>

<h3>Cheat Sheet</h3>
<pre><code># Basic enum (passive, all 37 APIs)
vulneagle -d target.com -se

# Enum with live filtering
vulneagle -d target.com -se -sc -live -o target_live

# Only free sources
vulneagle -d target.com -se --lite

# Root brute + status codes
vulneagle -d target.com -sb -w wordlists/subdomains.txt --resolver-file resolvers.txt -sc

# Passive + brute (separate runs)
vulneagle -d target.com -se -o enum
vulneagle -d target.com -sb -w wordlists/subdomains.txt --resolver-file resolvers.txt -o brute

# Directory brute only (single host)
python vulneagle.py -d https://app.target.com -db -w wordlists/directories.txt --recursion --rec-depth 2 -o dirs
</code></pre>

<h3>Core Modes</h3>
<ul>
  <li><code>-se</code> Passive enumeration</li>
  <li><code>-sb</code> DNS brute force (requires <code>-w</code> + <code>--resolver-file</code>)</li>
  <li><code>-db</code> Directory brute force (single host; uses the same <code>-w</code> wordlist)</li>
</ul>

<!-- Full scan feature removed in v0.4.0 -->

<h3>Key Options (Essentials)</h3>
<ul>
  <li><code>-w</code> Wordlist used for both subdomain (-sb) and directory (-db) brute forcing</li>
  <li><code>--resolver-file</code> Resolver IPs (required for brute forcing)</li>
  <li><code>-t</code> Threads (applies to all brute forcing, default 50)</li>
  <li><code>-sc</code> Probe HTTP status for discovered subdomains</li>
  <li><code>-live</code> Report only live subdomains (adds scheme://host & status)</li>
  <li><code>--resolver-check</code> UDP/53 reachability test for resolvers</li>
  <!-- nested brute + dir-limit removed with full scan deprecation -->
  <li><code>--recursion / --rec-depth</code> Enable recursive directory enumeration (depth 1–5)</li>
  <li><code>--rec-max-dirs</code> Limit recursive directory breadth (default 200)</li>
  <li><code>--rate-limit</code> Approx requests/sec throttle (directory brute)</li>
  <li><code>-r</code> txt|json output format (default txt)</li>
  <li><code>-o</code> Output prefix</li>
  <li><code>-q / -v</code> Quiet / Verbose modes</li>
  <li><code>--version</code> Show version</li>
</ul>

<h3>Resolver File (Example)</h3>
<pre><code># comments allowed
1.1.1.1
8.8.8.8
9.9.9.9
</code></pre>

<h3>Examples</h3>
<pre><code># Passive enumeration
python vulneagle.py -d example.com -se -o enum

# Passive enumeration live-only
python vulneagle.py -d example.com -se -sc -live -o enum_live

# DNS brute force (status probing)
python vulneagle.py -d example.com -sb -w wordlists/subdomains.txt --resolver-file resolvers.txt -sc -o brute

# Directory brute force (reuse -w)
python vulneagle.py -d https://app.example.com -db -w wordlists/directories.txt -o dirs

# Directory brute force (recursive depth 3)
python vulneagle.py -d https://app.example.com -db -w wordlists/directories.txt --recursion --rec-depth 3 -o dirs_rec

<!-- Full scan example removed -->
</code></pre>

<!-- Provider config section removed (keys now undocumented intentionally) -->

<h2>Contributing</h2>
<p>Fork → branch → commit → PR. File issues or feature requests in <a href="https://github.com/Parvesh776/VulnEagle/issues">Issues</a>.</p>

<h2>📄 License</h2>
<p>MIT License. See <code>LICENSE</code>.</p>

<p><strong>Project:</strong> VulnEagle | <strong>Author:</strong> <a href="https://github.com/Parvesh776">@parvesh776</a></p>
<hr/>
