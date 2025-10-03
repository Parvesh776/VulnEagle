# VulnEagle - API Keys Configuration Guide

## 📍 Where to Add API Keys

### **After Installation**
```bash
sudo nano /usr/share/vulneagle/recon/provider-config.yaml
```

### **Before Installation (Development)**
```bash
nano recon/provider-config.yaml
```

### **Via Environment Variables**
```bash
# Add to ~/.bashrc or ~/.zshrc
export VE_VIRUSTOTAL_KEY="your_api_key_here"
export VE_SHODAN_KEY="your_api_key_here"
export VE_SECURITYTRAILS_KEY="your_api_key_here"
```

---

## 🔑 How to Add API Keys

### **Config File Format**

```yaml
# Single API key
virustotal: "abc123def456..."
shodan: "ABCDEF123456..."
securitytrails: "st_api_key_..."

# Multiple keys (rotation)
urlscan:
  - "key_1_primary"
  - "key_2_backup"
  - "key_3_rotation"

# Special formats
censys: "API_ID:SECRET_KEY"
passivetotal: "USERNAME:API_SECRET"

# Leave empty if no key
chaos: []
github: []
```

### **Environment Variables Format**

```bash
# Primary format
export VE_VIRUSTOTAL_KEY="your_key"
export VE_SHODAN_KEY="your_key"

# Alternative formats (also supported)
export VE_VIRUSTOTAL="your_key"
export VIRUSTOTAL_KEY="your_key"
```

---

## 📋 Available API Providers (37 Total)

### **Free APIs (No Key Required) - 11 Sources**
These work without API keys:
- ✅ **crt.sh** - SSL certificate transparency logs
- ✅ **JLDC** - JLDC subdomain database
- ✅ **RapidDNS** - Rapid DNS enumeration
- ✅ **BufferOver** - DNS dataset
- ✅ **CommonCrawl** - Web crawl data
- ✅ **Wayback** - Internet Archive
- ✅ **AlienVault** - Open threat intelligence
- ✅ **ThreatMiner** - Threat intelligence portal
- ✅ **HackerTarget** - Online security tools
- ✅ **Robtex** - Network/DNS research
- ✅ **DNSDumpster** - DNS recon tool

### **API Key Required - 26 Premium Sources**

#### **🌟 High Priority (Most Useful Free Tiers)**

| Provider | Free Tier | Sign Up Link |
|----------|-----------|--------------|
| **VirusTotal** | 500 req/day | https://www.virustotal.com/gui/join-us |
| **URLScan.io** | 100 scans/day | https://urlscan.io/user/signup |
| **SecurityTrails** | 50 API calls/month | https://securitytrails.com/ |
| **Shodan** | 100 results | https://account.shodan.io/register |
| **Chaos** | Free tier | https://chaos.projectdiscovery.io/ |

**Config Example:**
```yaml
virustotal: "abc123..."
urlscan: "def456..."
securitytrails: "ghi789..."
shodan: "jkl012..."
chaos: "mno345..."
```

#### **⭐ Medium Priority**

| Provider | Description | Link |
|----------|-------------|------|
| **CertSpotter** | SSL cert monitoring | https://sslmate.com/certspotter/ |
| **BinaryEdge** | Internet scanner | https://app.binaryedge.io/ |
| **Netlas** | Internet asset search | https://app.netlas.io/ |
| **FullHunt** | Attack surface | https://fullhunt.io/ |
| **LeakIX** | Data leak search | https://leakix.net/ |
| **GitHub** | Code search | https://github.com/settings/tokens |
| **Hunter.io** | Email finder | https://hunter.io/ |

**Config Example:**
```yaml
certspotter: "your_key"
binaryedge: "your_key"
netlas: "your_key"
fullhunt: "your_key"
leakix: "your_key"
github: "ghp_your_token"
hunter: "your_key"
```

#### **🔧 Advanced/Paid**

| Provider | Format | Link |
|----------|--------|------|
| **Censys** | `API_ID:SECRET` | https://search.censys.io/account/api |
| **PassiveTotal** | `USER:SECRET` | https://community.riskiq.com/ |
| **WhoisXML** | Standard | https://whoisxmlapi.com/ |
| **C99.nl** | Standard | https://api.c99.nl/ |
| **Spyse** | Standard | https://spyse.com/ |
| **BeVigil** | Standard | https://bevigil.com/ |
| **BuiltWith** | Standard | https://builtwith.com/ |
| **Riddler** | Standard | https://riddler.io/ |

**Config Example:**
```yaml
censys: "12345:secret_key_here"
passivetotal: "user@email.com:api_token"
whoisxmlapi: "your_key"
c99: "your_key"
spyse: "your_key"
bevigil: "your_key"
builtwith: "your_key"
riddler: "your_key"
```

#### **🌏 Regional/Chinese APIs**

| Provider | Region | Link |
|----------|--------|------|
| **FOFA** | China | https://fofa.info/ |
| **Quake360** | China | https://quake.360.cn/ |
| **ZoomEye** | China | https://www.zoomeye.org/ |
| **ThreatBook** | China | https://x.threatbook.com/ |
| **Chinaz** | China | https://my.chinaz.com/ |

**Config Example:**
```yaml
fofa: "your_key"
quake: "your_key"
zoomeye: "your_key"
threatbook: "your_key"
chinaz: "your_key"
```

#### **📚 Other Sources**

```yaml
dnsdb: "your_key"         # DNSDB by Farsight
dnsrepo: "your_key"       # DNS Repository
intelx: "your_key"        # Intelligence X
```

---

## 🎯 Recommended Configurations

### **Minimal Setup (3 Free APIs)**
Best for quick start:
```yaml
virustotal: "your_vt_key"
urlscan: "your_urlscan_key"
securitytrails: "your_st_key"
```

### **Balanced Setup (5-7 APIs)**
Good coverage without too many keys:
```yaml
virustotal: "your_key"
urlscan: "your_key"
securitytrails: "your_key"
shodan: "your_key"
chaos: "your_key"
certspotter: "your_key"
github: "ghp_token"
```

### **Maximum Coverage (15+ APIs)**
For comprehensive reconnaissance:
```yaml
# Free tier APIs
virustotal: "key"
urlscan: "key"
securitytrails: "key"
shodan: "key"
chaos: "key"
certspotter: "key"
binaryedge: "key"
netlas: "key"
fullhunt: "key"
leakix: "key"
github: "token"
hunter: "key"

# Paid/Advanced
censys: "id:secret"
passivetotal: "user:secret"
whoisxmlapi: "key"
```

---

## ✅ Verify Your Configuration

### **List Available Sources**
```bash
vulneagle -ls
# or
vulneagle --list-sources
```

### **Test with Verbose Mode**
```bash
vulneagle -d example.com -se -v
```

This will show:
- ✅ Which APIs have keys configured
- ✅ Which APIs are querying
- ✅ Which APIs returned results
- ❌ Which APIs failed/timed out

---

## 🔒 Security Best Practices

### **1. Protect Your Config File**
```bash
# Restrict permissions
chmod 600 /usr/share/vulneagle/recon/provider-config.yaml

# Or for development
chmod 600 recon/provider-config.yaml
```

### **2. Don't Commit Keys to Git**
```bash
# Add to .gitignore
echo "recon/provider-config.yaml" >> .gitignore
```

### **3. Use Environment Variables for CI/CD**
```bash
# In CI/CD pipelines, use env vars instead of config file
export VE_VIRUSTOTAL_KEY="${{ secrets.VT_KEY }}"
export VE_SHODAN_KEY="${{ secrets.SHODAN_KEY }}"
```

### **4. Use Read-Only/Query-Only Keys**
- Most APIs offer different permission levels
- Use query-only keys when available
- Don't use admin/write keys

### **5. Rotate Keys Regularly**
```yaml
# Use multiple keys for rotation
virustotal:
  - "key_1_primary"
  - "key_2_backup"
```

---

## 🆓 Get Free API Keys

### **Step-by-Step for Top 5**

#### **1. VirusTotal**
```
1. Go to: https://www.virustotal.com/gui/join-us
2. Sign up (free)
3. Go to Profile → API Key
4. Copy your key
5. Limit: 500 requests/day
```

#### **2. URLScan.io**
```
1. Go to: https://urlscan.io/user/signup
2. Sign up (free)
3. Go to Settings → API
4. Copy your key
5. Limit: 100 scans/day
```

#### **3. SecurityTrails**
```
1. Go to: https://securitytrails.com/
2. Sign up (free plan)
3. Dashboard → API
4. Copy your key
5. Limit: 50 API calls/month
```

#### **4. Shodan**
```
1. Go to: https://account.shodan.io/register
2. Sign up
3. Dashboard → My Account
4. Copy API Key
5. Free tier: 100 results
```

#### **5. Chaos (ProjectDiscovery)**
```
1. Go to: https://chaos.projectdiscovery.io/
2. Sign in with GitHub
3. Get API key
4. Free tier available
```

---

## 🐛 Troubleshooting

### **Keys Not Working?**

1. **Check file location:**
   ```bash
   ls -la /usr/share/vulneagle/recon/provider-config.yaml
   ```

2. **Validate YAML syntax:**
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('/usr/share/vulneagle/recon/provider-config.yaml'))"
   ```

3. **Check environment variables:**
   ```bash
   env | grep VE_
   ```

4. **Test with verbose mode:**
   ```bash
   vulneagle -d example.com -se -v 2>&1 | grep -i "error\|fail\|key"
   ```

### **Common Issues**

**Issue:** "API key invalid"
```
Solution: Check if key is correct and not expired
- Some APIs expire keys after inactivity
- Regenerate key from provider dashboard
```

**Issue:** "Rate limit exceeded"
```
Solution: Add multiple keys for rotation
virustotal:
  - "key1"
  - "key2"
```

**Issue:** "YAML parse error"
```
Solution: Check quotes and indentation
# Correct:
virustotal: "key"

# Wrong:
virustotal: key with spaces
```

---

## 📞 Support

- **Issues:** https://github.com/Parvesh776/VulnEagle/issues
- **Documentation:** https://github.com/Parvesh776/VulnEagle
- **Installation Guide:** [INSTALL_KALI.md](INSTALL_KALI.md)

---

**Happy Hunting! 🦅**
