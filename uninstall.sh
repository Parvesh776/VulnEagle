#!/bin/bash
# VulnEagle - Professional Uninstaller

set -e

echo "╔════════════════════════════════════════╗"
echo "║   VulnEagle - Uninstaller             ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root or with sudo"
    exit 1
fi

# Remove installation directory
if [ -d /usr/share/vulneagle ]; then
    echo "[*] Removing VulnEagle installation directory..."
    rm -rf /usr/share/vulneagle
    echo "[✓] Removed /usr/share/vulneagle"
fi

# Remove executable
if [ -f /usr/local/bin/vulneagle ]; then
    echo "[*] Removing system-wide executable..."
    rm -f /usr/local/bin/vulneagle
    echo "[✓] Removed /usr/local/bin/vulneagle"
fi

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  ✓ Uninstallation Complete!           ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "[*] Note: Python dependencies (requests, dnspython, pyyaml) were NOT removed"
echo "[*] To remove dependencies manually, run:"
echo "    pip3 uninstall requests dnspython pyyaml"
echo ""

