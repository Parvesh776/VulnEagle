#!/bin/bash
# VulnEagle - Quick Uninstaller for Kali Linux

set -e

echo "[*] VulnEagle - Uninstaller"
echo "==========================="
echo ""

# Remove symlink
if [ -L /usr/local/bin/vulneagle ]; then
    echo "[*] Removing system-wide executable..."
    sudo rm -f /usr/local/bin/vulneagle
    echo "[✓] Removed /usr/local/bin/vulneagle"
fi

echo ""
echo "[*] Note: Python dependencies (requests, dnspython, pyyaml) were NOT removed"
echo "[*] To remove dependencies, run:"
echo "    pip3 uninstall requests dnspython pyyaml"
echo ""
echo "[✓] Uninstallation complete!"
echo ""
