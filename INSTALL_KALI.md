# VulnEagle - Kali Linux Installation Guide

## Quick Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/Parvesh776/VulnEagle.git
cd VulnEagle

# Run installer (requires root)
chmod +x install.sh
sudo ./install.sh

# Installation script automatically cleans up and removes the directory
# You'll be returned to your home/parent directory

# Now use VulnEagle from anywhere
vulneagle -d example.com -se
```

## What Gets Installed?

- **Executable**: `/usr/local/bin/vulneagle`
- **Libraries**: `/usr/share/vulneagle/` (hidden from user)
- **Wordlists**: `/usr/share/vulneagle/wordlists/`
- **Config**: `/usr/share/vulneagle/recon/provider-config.yaml`

## Post-Installation

After installation, you'll have a clean system with:
- ✅ System-wide `vulneagle` command
- ✅ All files properly organized in `/usr/share/vulneagle/`
- ✅ No clutter in your home directory
- ✅ Professional installation like other security tools

## Usage Examples

```bash
# Subdomain enumeration
vulneagle -d tesla.com -se

# DNS brute force with custom wordlist
vulneagle -d tesla.com -sb -w /usr/share/vulneagle/wordlists/subdomains.txt

# Directory brute force
vulneagle -d https://example.com -db

# Status code check with live filtering
vulneagle -l subdomains.txt -sc -live

# Verbose mode
vulneagle -d example.com -se -v
```

## Configuration

Edit provider config for API keys:
```bash
sudo nano /usr/share/vulneagle/recon/provider-config.yaml
```

## Uninstallation

```bash
sudo /usr/share/vulneagle/uninstall.sh
```

This will:
- Remove `/usr/share/vulneagle/` directory
- Remove `/usr/local/bin/vulneagle` executable
- Keep Python dependencies (in case other tools use them)

## Manual Dependency Removal (Optional)

```bash
pip3 uninstall requests dnspython pyyaml
```

## System Requirements

- Kali Linux 2023.1+ (or Debian-based)
- Python 3.10 or higher
- Root access for installation

## Troubleshooting

### Permission Denied
```bash
# Make sure you run installer with sudo
sudo ./install.sh
```

### Command Not Found After Install
```bash
# Check if /usr/local/bin is in your PATH
echo $PATH | grep /usr/local/bin

# If not, add to ~/.bashrc or ~/.zshrc
export PATH="/usr/local/bin:$PATH"
```

### Dependencies Installation Failed
```bash
# Manually install via pip
pip3 install --break-system-packages requests dnspython pyyaml
```

## Development Setup (No Installation)

If you want to modify the tool without installing:

```bash
git clone https://github.com/Parvesh776/VulnEagle.git
cd VulnEagle
chmod +x vulneagle.py
./vulneagle.py -d example.com -se
```
