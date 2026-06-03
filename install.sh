#!/usr/bin/env bash
# =============================================================
#  ReconX — Install Script for Kali Linux / Parrot OS / Ubuntu
#  Usage: bash install.sh
# =============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
    ____                       _  __
   / __ \___  _________  ____  | |/ /
  / /_/ / _ \/ ___/ __ \/ __ \ |   /
 / _, _/  __/ /__/ /_/ / / / //   |
/_/ |_|\___/\___/\____/_/ /_//_/|_|
         Installation Script v1.0
BANNER
echo -e "${NC}"

# ── Root check ───────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    warn "Running without root — some apt installs may fail"
    warn "Consider: sudo bash install.sh"
fi

# ── Detect OS ────────────────────────────────────────────────
OS="unknown"
if   [[ -f /etc/kali_version ]]; then OS="kali"
elif [[ -f /etc/parrot-version ]]; then OS="parrot"
elif grep -qi ubuntu /etc/os-release 2>/dev/null; then OS="ubuntu"
elif grep -qi debian /etc/os-release 2>/dev/null; then OS="debian"
fi
info "Detected OS: $OS"

# ═════════════════════════════════════════════════════════════
# 1. APT packages
# ═════════════════════════════════════════════════════════════
info "Installing apt packages..."
apt_packages=(
    python3 python3-pip python3-venv
    nmap masscan
    whatweb wafw00f
    wpscan joomscan
    curl wget jq git
    dnsutils whois
    libssl-dev libffi-dev
    libpango-1.0-0 libpangocairo-1.0-0  # WeasyPrint deps
    libcairo2 libgdk-pixbuf2.0-0
)

if apt-get update -qq 2>/dev/null; then
    for pkg in "${apt_packages[@]}"; do
        if apt-get install -y -qq "$pkg" 2>/dev/null; then
            success "  $pkg"
        else
            warn "  $pkg — skipped (not found in repos)"
        fi
    done
else
    warn "apt-get update failed — skipping system packages"
fi

# ═════════════════════════════════════════════════════════════
# 2. Go tools
# ═════════════════════════════════════════════════════════════
info "Checking Go installation..."
if ! command -v go &>/dev/null; then
    warn "Go not found — installing..."
    GO_VER="1.22.3"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
    echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >> "$HOME/.bashrc"
    success "Go $GO_VER installed"
else
    success "Go already installed: $(go version)"
fi
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/edoardottt/cariddi/cmd/cariddi@latest"
    "github.com/assetnote/kiterunner/cmd/kiterunner@latest"
)

info "Installing Go security tools..."
for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    if command -v "$name" &>/dev/null; then
        success "  $name — already installed"
    else
        info "  Installing $name..."
        if GOPATH="$HOME/go" go install "$tool" 2>/dev/null; then
            success "  $name — installed"
        else
            warn "  $name — failed"
        fi
    fi
done

# amass (separate — heavier)
if ! command -v amass &>/dev/null; then
    info "Installing amass..."
    GOPATH="$HOME/go" go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null \
        && success "  amass — installed" \
        || warn "  amass — failed (optional)"
fi

# ═════════════════════════════════════════════════════════════
# 3. droopescan (pip)
# ═════════════════════════════════════════════════════════════
info "Installing droopescan..."
if pip3 install droopescan -q --break-system-packages 2>/dev/null || pip3 install droopescan -q 2>/dev/null; then
    success "droopescan installed"
else
    warn "droopescan — failed"
fi

# ═════════════════════════════════════════════════════════════
# 3b. Endpoint-discovery tools: LinkFinder + xnLinkFinder
# ═════════════════════════════════════════════════════════════
info "Installing xnLinkFinder (pip)..."
if pip3 install xnLinkFinder -q --break-system-packages 2>/dev/null || pip3 install xnLinkFinder -q 2>/dev/null; then
    success "xnLinkFinder installed"
else
    warn "xnLinkFinder — failed"
fi

LINKFINDER_DIR="/opt/LinkFinder"
if [[ ! -d "$LINKFINDER_DIR" ]]; then
    info "Cloning LinkFinder..."
    if git clone --depth 1 https://github.com/GerbenJavado/LinkFinder "$LINKFINDER_DIR" 2>/dev/null; then
        pip3 install -r "$LINKFINDER_DIR/requirements.txt" -q --break-system-packages 2>/dev/null \
            || pip3 install -r "$LINKFINDER_DIR/requirements.txt" -q 2>/dev/null || true
        success "LinkFinder → $LINKFINDER_DIR (set scan.endpoint_harvester.linkfinder_path if needed)"
    else
        warn "LinkFinder clone failed"
    fi
else
    success "LinkFinder already at $LINKFINDER_DIR"
fi

# ═════════════════════════════════════════════════════════════
# 3c. XSS scanners: XSStrike + XSSer
# ═════════════════════════════════════════════════════════════
info "Installing XSSer (apt)..."
apt-get install -y -qq xsser 2>/dev/null && success "xsser installed" || warn "xsser — install manually if needed"

XSSTRIKE_DIR="/opt/XSStrike"
if [[ ! -d "$XSSTRIKE_DIR" ]]; then
    info "Cloning XSStrike..."
    if git clone --depth 1 https://github.com/s0md3v/XSStrike "$XSSTRIKE_DIR" 2>/dev/null; then
        pip3 install -r "$XSSTRIKE_DIR/requirements.txt" -q --break-system-packages 2>/dev/null \
            || pip3 install -r "$XSSTRIKE_DIR/requirements.txt" -q 2>/dev/null || true
        success "XSStrike → $XSSTRIKE_DIR (set scan.xss.xsstrike_path if not on PATH)"
    else
        warn "XSStrike clone failed"
    fi
else
    success "XSStrike already at $XSSTRIKE_DIR"
fi

# ═════════════════════════════════════════════════════════════
# 4. Nuclei templates
# ═════════════════════════════════════════════════════════════
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates -silent && success "Nuclei templates updated" || warn "Nuclei templates update failed"
fi

# ═════════════════════════════════════════════════════════════
# 5. SecLists wordlists
# ═════════════════════════════════════════════════════════════
SECLISTS_DIR="/opt/SecLists"
if [[ ! -d "$SECLISTS_DIR" ]]; then
    info "Cloning SecLists..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists "$SECLISTS_DIR" \
        && success "SecLists → $SECLISTS_DIR" \
        || warn "SecLists clone failed"
else
    success "SecLists already at $SECLISTS_DIR"
fi

# ═════════════════════════════════════════════════════════════
# 6. Ollama (local AI)
# ═════════════════════════════════════════════════════════════
info "Checking Ollama..."
if ! command -v ollama &>/dev/null; then
    info "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null \
        && success "Ollama installed" \
        || warn "Ollama install failed — run manually: curl -fsSL https://ollama.com/install.sh | sh"
else
    success "Ollama already installed: $(ollama --version 2>/dev/null || echo 'unknown version')"
fi

# Pull default model
if command -v ollama &>/dev/null; then
    MODEL="deepseek-r1:7b"
    info "Pulling Ollama model: $MODEL"
    warn "(~4GB download — this may take a while)"
    ollama pull "$MODEL" && success "Model $MODEL ready" || warn "Pull failed — run: ollama pull $MODEL"
fi

# ═════════════════════════════════════════════════════════════
# 7. Python venv + pip packages
# ═════════════════════════════════════════════════════════════
info "Setting up Python virtual environment..."
cd "$SCRIPT_DIR"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate 2>/dev/null || true

pip install --upgrade pip -q
pip install -r requirements.txt -q \
    && success "Python dependencies installed" \
    || warn "Some pip packages failed — check requirements.txt"

# ═════════════════════════════════════════════════════════════
# 8. Tool summary
# ═════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Tool Status${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"

TOOLS=(
    nmap masscan subfinder amass assetfinder dnsx httpx
    nuclei interactsh-client katana ffuf whatweb wafw00f wpscan joomscan
    droopescan arjun gowitness waybackurls gau ollama
    cariddi kiterunner xnLinkFinder
    dalfox xsser
)

FOUND=0; MISSING=0
for t in "${TOOLS[@]}"; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $t"
        FOUND=$((FOUND+1))
    else
        echo -e "  ${YELLOW}✗${NC} $t"
        MISSING=$((MISSING+1))
    fi
done

echo ""
echo -e "  ${GREEN}Installed: $FOUND${NC}  |  ${YELLOW}Missing: $MISSING${NC}"
echo ""

# ═════════════════════════════════════════════════════════════
# 9. Usage instructions
# ═════════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}Installation complete!${NC}"
echo ""
echo -e "${BOLD}Usage:${NC}"
echo "  source .venv/bin/activate          # activate venv (first time)"
echo "  python3 main.py --target example.com"
echo "  python3 main.py --target example.com --modules recon,portscan"
echo "  python3 main.py --target example.com --skip vulnscan"
echo "  python3 main.py --target example.com --resume"
echo ""
echo -e "${BOLD}Config:${NC}"
echo "  nano config.yaml                   # set Telegram token, AI model, etc."
echo ""
echo -e "${BOLD}Ollama (if not started):${NC}"
echo "  ollama serve &"
echo "  ollama pull deepseek-r1:7b"
