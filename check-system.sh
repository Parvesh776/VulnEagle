#!/bin/bash
# VulnEagle - System Check Script for Kali Linux
# Run this to verify your system is ready for VulnEagle

echo "╔════════════════════════════════════════╗"
echo "║  VulnEagle - System Check (Kali)      ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -n "[*] Checking Python version... "
if command -v python3 &> /dev/null; then
    PYTHON_VER=$(python3 --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo $PYTHON_VER | cut -d. -f1)
    MINOR=$(echo $PYTHON_VER | cut -d. -f2)
    
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
        echo -e "${GREEN}✓${NC} Python $PYTHON_VER"
    else
        echo -e "${RED}✗${NC} Python $PYTHON_VER (need 3.10+)"
        exit 1
    fi
else
    echo -e "${RED}✗${NC} Python3 not found"
    exit 1
fi

# Check pip
echo -n "[*] Checking pip... "
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓${NC} pip3 available"
else
    echo -e "${RED}✗${NC} pip3 not found"
    echo "    Install: sudo apt install python3-pip"
    exit 1
fi

# Check dependencies
echo ""
echo "[*] Checking Python dependencies:"

check_module() {
    if python3 -c "import $1" 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "    ${RED}✗${NC} $1 (missing)"
        return 1
    fi
}

MISSING=0
check_module "requests" || MISSING=1
check_module "dns.resolver" || MISSING=1
check_module "yaml" || echo -e "    ${YELLOW}⚠${NC} yaml (optional)"

# Check wordlists
echo ""
echo "[*] Checking wordlists:"
if [ -d "wordlists" ]; then
    echo -e "    ${GREEN}✓${NC} wordlists/ directory exists"
    
    if [ -f "wordlists/subdomains.txt" ]; then
        LINES=$(wc -l < wordlists/subdomains.txt)
        echo -e "    ${GREEN}✓${NC} subdomains.txt ($LINES entries)"
    else
        echo -e "    ${YELLOW}⚠${NC} subdomains.txt missing"
    fi
    
    if [ -f "wordlists/resolvers.txt" ]; then
        LINES=$(wc -l < wordlists/resolvers.txt)
        echo -e "    ${GREEN}✓${NC} resolvers.txt ($LINES entries)"
    else
        echo -e "    ${YELLOW}⚠${NC} resolvers.txt missing"
    fi
else
    echo -e "    ${YELLOW}⚠${NC} wordlists/ directory missing"
fi

# Check provider config
echo ""
echo "[*] Checking configuration:"
if [ -f "recon/provider-config.yaml" ]; then
    echo -e "    ${GREEN}✓${NC} provider-config.yaml exists"
else
    echo -e "    ${YELLOW}⚠${NC} provider-config.yaml missing"
fi

# Summary
echo ""
echo "════════════════════════════════════════"
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}[✓] System is ready for VulnEagle!${NC}"
    echo ""
    echo "Quick start:"
    echo "  ./vulneagle.py -d example.com -se"
    echo ""
    echo "For system-wide install:"
    echo "  sudo ./install.sh"
else
    echo -e "${RED}[!] Missing dependencies detected${NC}"
    echo ""
    echo "Install missing modules:"
    echo "  pip3 install --break-system-packages requests dnspython pyyaml"
    echo ""
    echo "Or use system packages:"
    echo "  sudo apt install python3-requests python3-dnspython python3-yaml"
fi
echo "════════════════════════════════════════"
