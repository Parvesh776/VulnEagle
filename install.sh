#!/bin/bash
# VulnEagle - Kali Linux Installation Script
# This installs VulnEagle system-wide on Kali Linux

set -e

echo "[*] VulnEagle - Kali Linux Installer"
echo "======================================"
echo ""

# Check if running on Kali/Debian-based system
if [ ! -f /etc/debian_version ]; then
    echo "[!] Warning: This script is optimized for Debian/Kali Linux"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "[!] Error: Python 3.10+ required. Current version: $PYTHON_VERSION"
    exit 1
fi

echo "[+] Python version: $PYTHON_VERSION ✓"

# Install system dependencies
echo ""
echo "[*] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y python3-pip python3-requests python3-yaml python3-dnspython 2>/dev/null || {
        echo "[!] Some packages failed, will use pip fallback"
    }
fi

# Install Python dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install --break-system-packages requests dnspython pyyaml 2>/dev/null || pip3 install requests dnspython pyyaml

# Create symlink in /usr/local/bin
echo ""
echo "[*] Creating system-wide executable..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo ln -sf "$SCRIPT_DIR/vulneagle.py" /usr/local/bin/vulneagle
sudo chmod +x "$SCRIPT_DIR/vulneagle.py"
sudo chmod +x /usr/local/bin/vulneagle

# Create wordlists directory if needed
if [ ! -d "$SCRIPT_DIR/wordlists" ]; then
    mkdir -p "$SCRIPT_DIR/wordlists"
fi

echo ""
echo "======================================"
echo "[✓] Installation Complete!"
echo ""
echo "Usage:"
echo "  vulneagle -d example.com -se          # Subdomain enumeration"
echo "  vulneagle -d example.com -sb -w wordlists/subdomains.txt --resolver-file wordlists/resolvers.txt"
echo "  vulneagle -d https://example.com -db  # Directory bruteforce"
echo "  vulneagle -l hosts.txt -sc -live      # Live host detection"
echo ""
echo "Config file: $SCRIPT_DIR/recon/provider-config.yaml"
echo ""
