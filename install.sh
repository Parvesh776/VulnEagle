#!/bin/bash
# VulnEagle - Professional Installation Script
# Installs VulnEagle system-wide with clean directory structure

set -e

echo "╔════════════════════════════════════════╗"
echo "║   VulnEagle - Installation Script     ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root or with sudo"
    exit 1
fi

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
    apt-get update -qq
    apt-get install -y python3-pip python3-requests python3-yaml python3-dnspython 2>/dev/null || {
        echo "[!] Some packages failed, will use pip fallback"
    }
fi

# Install Python dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install --break-system-packages requests dnspython pyyaml 2>/dev/null || pip3 install requests dnspython pyyaml

# Define installation paths
INSTALL_DIR="/usr/share/vulneagle"
BIN_PATH="/usr/local/bin/vulneagle"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create installation directory
echo ""
echo "[*] Installing VulnEagle to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy all necessary files to installation directory
cp -r "$SCRIPT_DIR/recon" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/scanner" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/auth" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/wordlists" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/vulneagle.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/_init_.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/"

# Set permissions
chmod -R 755 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/vulneagle.py"
chmod +x "$INSTALL_DIR/uninstall.sh"

# Create wrapper script in /usr/local/bin
echo ""
echo "[*] Creating system-wide executable..."
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
# VulnEagle wrapper script
exec python3 /usr/share/vulneagle/vulneagle.py "$@"
EOF

chmod +x "$BIN_PATH"

# Clean up installation directory (remove git files if present)
rm -rf "$INSTALL_DIR/.git" 2>/dev/null || true
rm -rf "$INSTALL_DIR/.gitignore" 2>/dev/null || true

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  ✓ Installation Complete!             ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "VulnEagle is now installed system-wide!"
echo ""
echo "Usage Examples:"
echo "  vulneagle -d example.com -se          # Subdomain enumeration"
echo "  vulneagle -d example.com -sb -w /usr/share/vulneagle/wordlists/subdomains.txt"
echo "  vulneagle -d https://example.com -db  # Directory bruteforce"
echo "  vulneagle -l hosts.txt -sc -live      # Live host detection"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Config file: $INSTALL_DIR/recon/provider-config.yaml"
echo ""
echo "[*] Cleaning up installation files..."

# Get parent directory before deleting
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# Delete the cloned VulnEagle directory
if [ -d "$SCRIPT_DIR" ]; then
    cd "$PARENT_DIR"
    rm -rf "$SCRIPT_DIR"
    echo "[✓] Removed installation directory: $SCRIPT_DIR"
fi

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  VulnEagle is ready to use!           ║"
echo "║  Type: vulneagle -h                   ║"
echo "╚════════════════════════════════════════╝"
echo ""
