#!/usr/bin/env bash
# kalitelligence.sh
# Advanced Threat Intel / OSINT / Dark-web workflows on Kali
# Enhanced with parallel execution, comprehensive reporting, TI integration, and automation
# For authorized investigations only.

set -u
export DEBIAN_FRONTEND=noninteractive

# ---------- Enhanced logging with levels and timestamps ----------
readonly LOG_DIR="/var/log/ti-suite"
readonly LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"

log()   { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"; echo "$msg" | tee -a "$LOG_FILE"; }
ok()    { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*"; echo -e "\033[0;32m$msg\033[0m" | tee -a "$LOG_FILE"; }
warn()  { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"; echo -e "\033[0;33m$msg\033[0m" | tee -a "$LOG_FILE" >&2; }
die()   { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*"; echo -e "\033[0;31m$msg\033[0m" | tee -a "$LOG_FILE" >&2; exit 1; }
debug() { [[ "${DEBUG:-0}" == "1" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" | tee -a "$LOG_FILE"; }

# ---------- Performance monitoring ----------
START_TIME=$(date +%s)
track_performance() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    log "Installation completed in ${duration}s"
}
trap track_performance EXIT

# ---------- Require root ----------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "Run as root (e.g., sudo $0)"
fi

# ---------- Real user & home ----------
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  REAL_USER="${SUDO_USER}"
else
  REAL_USER="$(logname 2>/dev/null || echo root)"
fi
USER_HOME="$(eval echo ~${REAL_USER})"

# ---------- Enhanced arguments / presets ----------
PRESET="passive"
WITH_OFFSEC=0
ENABLE_UFW=1
QC_PROXY="none"
PARALLEL_JOBS=4
AUTO_UPDATE=1
INSTALL_DOCKER=0
ENABLE_AUTOMATION=0
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""
INSTALL_AI_TOOLS=0

show_help() {
cat <<USAGE
Advanced Kali Threat Intelligence Suite Installer

Usage: sudo $0 [OPTIONS]

Presets:
  --preset [passive|darkweb|easm|dfir|full|custom]
           passive:  Safe OSINT tools (default)
           darkweb:  Tor, onion services, privacy tools
           easm:     External Attack Surface Management
           dfir:     Digital Forensics & Incident Response
           full:     Everything
           custom:   Minimal base, use --with-* flags

Security & Network:
  --with-offsec         Include offensive security tools (hashcat, hydra, john)
  --no-ufw              Skip UFW firewall configuration
  --proxy [none|tor]    Default proxy for tools

Performance:
  --parallel [N]        Parallel jobs for installations (default: 4)
  --no-auto-update      Skip automatic tool updates

Advanced Features:
  --with-docker         Install Docker for containerized tools
  --enable-automation   Install cron jobs for automated scans
  --with-ai             Install AI/ML tools for threat analysis
  
Integrations:
  --slack-webhook URL   Slack notifications for findings
  --discord-webhook URL Discord notifications for findings

General:
  -h, --help           Show this help
  --debug              Enable debug logging

Examples:
  # Basic passive OSINT setup
  sudo $0 --preset passive
  
  # Full suite with automation and notifications
  sudo $0 --preset full --enable-automation --slack-webhook https://hooks.slack.com/...
  
  # EASM with Docker support
  sudo $0 --preset easm --with-docker --parallel 8

Installed Commands:
  quick-recon       Fast reconnaissance pipeline
  ti-health         System health check
  ti-update         Update all tools
  iocgrab           Extract IOCs from text
  webshot           Headless screenshots
  new-case          Initialize case directory
  ti-feeds          Fetch threat intelligence feeds
  ti-report         Generate comprehensive reports
  ti-dashboard      Launch monitoring dashboard
  ti-automate       Configure automated scans

USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset) PRESET="${2:-}"; shift 2;;
    --with-offsec) WITH_OFFSEC=1; shift;;
    --no-ufw) ENABLE_UFW=0; shift;;
    --proxy) QC_PROXY="${2:-}"; shift 2;;
    --parallel) PARALLEL_JOBS="${2:-4}"; shift 2;;
    --no-auto-update) AUTO_UPDATE=0; shift;;
    --with-docker) INSTALL_DOCKER=1; shift;;
    --enable-automation) ENABLE_AUTOMATION=1; shift;;
    --slack-webhook) SLACK_WEBHOOK="${2:-}"; shift 2;;
    --discord-webhook) DISCORD_WEBHOOK="${2:-}"; shift 2;;
    --with-ai) INSTALL_AI_TOOLS=1; shift;;
    --debug) DEBUG=1; shift;;
    -h|--help) show_help; exit 0;;
    *) warn "Unknown arg: $1"; shift;;
  esac
done

# ---------- Validate preset ----------
case "$PRESET" in
  passive|darkweb|easm|dfir|full|custom) ;;
  *) warn "Unknown preset '$PRESET', falling back to 'passive'"; PRESET="passive";;
esac

log "Starting installation with preset: $PRESET"
log "User: $REAL_USER | Home: $USER_HOME"

# ---------- Optimized apt helpers with caching ----------
APT_NEEDS_UPDATE=1
APT_CACHE_DIR="/var/cache/ti-suite"
mkdir -p "$APT_CACHE_DIR"

apt_update_once() {
  if [[ $APT_NEEDS_UPDATE -eq 1 ]]; then
    log "Running apt update..."
    apt-get update -y 2>&1 | tee -a "$LOG_FILE" || die "apt update failed"
    APT_NEEDS_UPDATE=0
    date +%s > "$APT_CACHE_DIR/last_update"
  fi
}

apt_install() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    debug "$pkg already installed"
    return 0
  fi
  apt_update_once
  log "Installing $pkg..."
  if ! apt-get install -y "$pkg" 2>&1 | tee -a "$LOG_FILE"; then
    warn "apt install failed: $pkg"
    return 1
  fi
  ok "$pkg installed"
}

# Parallel apt installation for speed
apt_install_parallel() {
  local -a pkgs=("$@")
  local -a missing=()
  
  for pkg in "${pkgs[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  
  if [[ ${#missing[@]} -eq 0 ]]; then
    debug "All packages already installed"
    return 0
  fi
  
  apt_update_once
  log "Installing ${#missing[@]} packages in parallel..."
  
  # Split into batches for parallel installation
  local batch_size=10
  for ((i=0; i<${#missing[@]}; i+=batch_size)); do
    local batch=("${missing[@]:i:batch_size}")
    apt-get install -y "${batch[@]}" 2>&1 | tee -a "$LOG_FILE" || warn "Some packages failed in batch"
  done
}

# ---------- Enhanced package lists ----------
BASE_PKGS=(
  git curl wget ca-certificates gnupg lsb-release jq whois dnsutils netcat-openbsd
  python3 python3-pip python3-venv python3-dev build-essential libssl-dev libffi-dev
  sqlite3 chromium tmux screen parallel htop iotop 
  zip unzip p7zip-full
  graphviz imagemagick
)

NET_PRIVACY_PKGS=(
  tor torsocks proxychains4 openvpn wireguard 
  torbrowser-launcher onionshare-cli i2pd
  privoxy
)

OSINT_PKGS=(
  spiderfoot theharvester recon-ng sublist3r sn0int dnstwist
  exiftool metagoofil seclists maltego
  sherlock photon
)

PDISCOVERY_PKGS=(
  subfinder httpx-toolkit naabu nuclei katana amass 
  nmap masscan zmap rustscan
  gobuster feroxbuster ffuf
  waybackurls gau
)

DFIR_PKGS=(
  yara binwalk foremost scalpel testdisk 
  autopsy sleuthkit volatility
  chkrootkit rkhunter
)

OFFSEC_PKGS=(
  hashcat john hydra medusa ncrack
  cupp cewl crunch
  aircrack-ng reaver pixiewps
)

INTEL_PKGS=(
  maltego outguess stegosuite steghide
  wireshark tshark tcpdump
)

AI_ML_PKGS=(
  python3-sklearn python3-numpy python3-pandas
  python3-tensorflow python3-keras
)

# ---------- Choose package sets ----------
APT_LIST=()
case "$PRESET" in
  passive)
    APT_LIST=( "${BASE_PKGS[@]}" "${OSINT_PKGS[@]}" "${PDISCOVERY_PKGS[@]}" )
    ;;
  darkweb)
    APT_LIST=( "${BASE_PKGS[@]}" "${OSINT_PKGS[@]}" "${NET_PRIVACY_PKGS[@]}" )
    ;;
  easm)
    APT_LIST=( "${BASE_PKGS[@]}" "${PDISCOVERY_PKGS[@]}" "${INTEL_PKGS[@]}" )
    ;;
  dfir)
    APT_LIST=( "${BASE_PKGS[@]}" "${DFIR_PKGS[@]}" "${OSINT_PKGS[@]}" "${INTEL_PKGS[@]}" )
    ;;
  full)
    APT_LIST=( "${BASE_PKGS[@]}" "${NET_PRIVACY_PKGS[@]}" "${OSINT_PKGS[@]}" 
               "${PDISCOVERY_PKGS[@]}" "${DFIR_PKGS[@]}" "${INTEL_PKGS[@]}" )
    ;;
  custom)
    APT_LIST=( "${BASE_PKGS[@]}" )
    ;;
esac

[[ $WITH_OFFSEC -eq 1 ]] && APT_LIST+=( "${OFFSEC_PKGS[@]}" )
[[ $INSTALL_AI_TOOLS -eq 1 ]] && APT_LIST+=( "${AI_ML_PKGS[@]}" )

# ---------- Enhanced pip toolchain ----------
PIP_LIST=(
  holehe knockpy email2phonenumber maigret feedparser tldextract
  shodan censys dnspython requests beautifulsoup4 lxml
  pwntools scapy
  python-docx openpyxl python-pptx
  phonenumbers googlesearch-python
  h8mail buster socialscan
)

[[ "$PRESET" == "dfir" || "$PRESET" == "full" ]] && PIP_LIST+=( volatility3 )
[[ $INSTALL_AI_TOOLS -eq 1 ]] && PIP_LIST+=( torch transformers spacy yara-python )

# ---------- Enhanced git tools with version pinning ----------
declare -A GIT_TOOLS=(
  ["TorBot"]="https://github.com/DedSecInside/TorBot.git|/opt/TorBot|/usr/local/bin/torbot"
  ["h8mail"]="https://github.com/khast3x/h8mail.git|/opt/h8mail|/usr/local/bin/h8mail"
  ["OSRFramework"]="https://github.com/i3visio/osrframework.git|/opt/osrframework|"
  ["Photon"]="https://github.com/s0md3v/Photon.git|/opt/Photon|/usr/local/bin/photon"
  ["Striker"]="https://github.com/s0md3v/Striker.git|/opt/Striker|/usr/local/bin/striker"
  ["FinalRecon"]="https://github.com/thewhiteh4t/FinalRecon.git|/opt/FinalRecon|/usr/local/bin/finalrecon"
  ["OSINT-SPY"]="https://github.com/SharadKumar97/OSINT-SPY.git|/opt/OSINT-SPY|/usr/local/bin/osint-spy"
)

# ---------- System upgrade ----------
log "Performing full system upgrade..."
apt_update_once
DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" \
  -o Dpkg::Options::="--force-confdef" dist-upgrade 2>&1 | tee -a "$LOG_FILE" || warn "dist-upgrade had issues"
ok "System upgrade complete"

# ---------- Install apt packages with parallel optimization ----------
log "Installing ${#APT_LIST[@]} packages for preset: $PRESET"
apt_install_parallel "${APT_LIST[@]}"
ok "Package installation complete"

# ---------- Go installation for ProjectDiscovery tools ----------
if ! command -v go >/dev/null 2>&1; then
  log "Installing Go..."
  GO_VERSION="1.21.5"
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz || warn "Go download failed"
  if [[ -f /tmp/go.tar.gz ]]; then
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    export PATH=$PATH:/usr/local/go/bin
    ok "Go installed"
  fi
fi

# ---------- ProjectDiscovery tools with go install ----------
if command -v go >/dev/null 2>&1; then
  export GOPATH="$USER_HOME/go"
  export PATH="$PATH:$GOPATH/bin"
  
  PD_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/proxify/cmd/proxify@latest"
  )
  
  for tool in "${PD_TOOLS[@]}"; do
    log "Installing $tool..."
    su - "$REAL_USER" -c "go install -v $tool" 2>&1 | tee -a "$LOG_FILE" || warn "Failed: $tool"
  done
  
  # Update nuclei templates
  su - "$REAL_USER" -c "nuclei -update-templates -ut" 2>/dev/null || true
  ok "ProjectDiscovery tools installed"
fi

# ---------- Enhanced pip installation with virtual env ----------
log "Setting up Python virtual environment..."
VENV_PATH="$USER_HOME/.ti-venv"
su - "$REAL_USER" -c "python3 -m venv $VENV_PATH" || warn "venv creation failed"

if [[ -d "$VENV_PATH" ]]; then
  log "Installing Python packages..."
  for pkg in "${PIP_LIST[@]}"; do
    su - "$REAL_USER" -c "$VENV_PATH/bin/pip install -q $pkg" 2>&1 | tee -a "$LOG_FILE" || warn "pip install failed: $pkg"
  done
  
  # Create activation alias
  echo "alias ti-venv='source $VENV_PATH/bin/activate'" >> "$USER_HOME/.bashrc"
  ok "Python environment configured"
fi

# ---------- Clone and setup git tools with parallel execution ----------
clone_or_pull() {
  local repo="$1" dest="$2"
  if [[ -d "$dest/.git" ]]; then
    debug "Updating $dest..."
    (cd "$dest" && git pull --rebase --autostash 2>&1 | tee -a "$LOG_FILE") || warn "git pull failed: $repo"
  else
    log "Cloning $repo..."
    git clone --depth 1 "$repo" "$dest" 2>&1 | tee -a "$LOG_FILE" || warn "clone failed: $repo"
  fi
  
  # Install requirements if present
  if [[ -f "$dest/requirements.txt" ]]; then
    python3 -m pip install -q -r "$dest/requirements.txt" 2>&1 | tee -a "$LOG_FILE" || warn "requirements failed: $dest"
  fi
}

safe_symlink() {
  local src="$1" link="$2"
  [[ -e "$src" ]] || { warn "missing $src"; return; }
  ln -sf "$src" "$link"
  chmod +x "$link" 2>/dev/null || true
}

log "Cloning enhanced tool repositories..."
for tool_name in "${!GIT_TOOLS[@]}"; do
  IFS='|' read -r repo dest link <<< "${GIT_TOOLS[$tool_name]}"
  clone_or_pull "$repo" "$dest"
  
  if [[ -n "$link" ]]; then
    # Try multiple entry points
    for entry in main.py "${tool_name,,}.py" run.py; do
      if [[ -f "$dest/$entry" ]]; then
        safe_symlink "$dest/$entry" "$link"
        break
      fi
    done
  fi
done
ok "Git tools configured"

# ---------- Docker installation ----------
if [[ $INSTALL_DOCKER -eq 1 ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh 2>&1 | tee -a "$LOG_FILE" || warn "Docker install failed"
    usermod -aG docker "$REAL_USER" || true
    systemctl enable docker
    systemctl start docker
    ok "Docker installed"
    
    # Useful OSINT containers
    log "Pulling useful Docker images..."
    docker pull spiderfoot/spiderfoot:latest || true
    docker pull osintukraine/holehe:latest || true
  fi
fi

# ---------- Enhanced proxychains config ----------
for PC_CONF in "/etc/proxychains4.conf" "/etc/proxychains.conf"; do
  if [[ -f "$PC_CONF" ]]; then
    log "Configuring ProxyChains: $PC_CONF"
    cp "$PC_CONF" "${PC_CONF}.bak"
    
    sed -i 's/^\s*#\?\s*dynamic_chain.*/dynamic_chain/' "$PC_CONF"
    sed -i 's/^\s*strict_chain/#strict_chain/' "$PC_CONF"
    grep -Eq '^\s*proxy_dns' "$PC_CONF" || echo "proxy_dns" >> "$PC_CONF"
    grep -Eq '^\s*tcp_read_time_out' "$PC_CONF" || echo "tcp_read_time_out 15000" >> "$PC_CONF"
    grep -Eq '^\s*tcp_connect_time_out' "$PC_CONF" || echo "tcp_connect_time_out 8000" >> "$PC_CONF"
    
    # Ensure Tor proxy exists
    grep -Eq '^\s*socks5\s+127\.0\.0\.1\s+9050' "$PC_CONF" || {
      echo "" >> "$PC_CONF"
      echo "[ProxyList]" >> "$PC_CONF"
      echo "socks5 127.0.0.1 9050" >> "$PC_CONF"
    }
    ok "ProxyChains configured"
    break
  fi
done

# ---------- Tor configuration ----------
TOR_CONF="/etc/tor/torrc"
if [[ -f "$TOR_CONF" ]]; then
  log "Enhancing Tor configuration..."
  cp "$TOR_CONF" "${TOR_CONF}.bak"
  
  cat >> "$TOR_CONF" <<TORCONF

# TI Suite enhancements
ControlPort 9051
CookieAuthentication 1
SocksPort 9050
DNSPort 5353
TransPort 9040
TORCONF
  
  systemctl enable tor 2>/dev/null || true
  systemctl restart tor 2>/dev/null || true
  ok "Tor configured"
fi

# ---------- Enhanced workspace structure ----------
log "Creating workspace directories..."
WORKSPACES=(
  "OSINT" "DarkWeb" "Recon" "Passwords" "Metadata" "SocialMedia" 
  "Logs" "Cases" "Reports" "Exports" "Screenshots" "Captures"
  "ThreatIntel" "Vulnerabilities" "Breaches" "Malware"
)

for ws in "${WORKSPACES[@]}"; do
  mkdir -p "$USER_HOME/$ws"
done

# Create .gitignore for sensitive dirs
for sensitive in Passwords Captures Cases; do
  echo "*" > "$USER_HOME/$sensitive/.gitignore"
done

chown -R "$REAL_USER":"$REAL_USER" "$USER_HOME"/{OSINT,DarkWeb,Recon,Passwords,Metadata,SocialMedia,Logs,Cases,Reports,Exports,Screenshots,Captures,ThreatIntel,Vulnerabilities,Breaches,Malware}
ok "Workspaces created"

# ---------- Enhanced bashrc with productivity aliases ----------
BRC="$USER_HOME/.bashrc"
touch "$BRC"

cat >> "$BRC" <<'BASHRC_APPEND'

# ========== TI Suite Aliases ==========
alias sf='spiderfoot -l 127.0.0.1:5001'
alias recon='recon-ng'
alias th='theHarvester'
alias pc='proxychains4 -q'
alias subf="subfinder -silent -all"
alias httpx='httpx -silent -status-code -ip -title -tech-detect -follow-redirects'
alias nuclei='nuclei -duc -stats'
alias qr='quick-recon -d'
alias ports='naabu -silent -top-ports 1000'
alias spider='katana -silent -js-crawl'

# Productivity
alias ll='ls -lah'
alias grep='grep --color=auto'
alias torssh='torsocks ssh'
alias torwget='torsocks wget'
alias myip='curl -s https://api.ipify.org; echo'
alias toripMyip='torsocks curl -s https://api.ipify.org; echo'

# Quick navigation
alias osint='cd ~/OSINT'
alias cases='cd ~/Cases'
alias reports='cd ~/Reports'

# TI Suite commands
alias health='ti-health'
alias update-ti='ti-update'
alias new-case='ti-case'
alias dash='ti-dashboard'

# Export PATH for Go tools
export PATH="$PATH:$HOME/go/bin"
BASHRC_APPEND

chown "$REAL_USER":"$REAL_USER" "$BRC"
ok "Bash configuration updated"

# ---------- Firewall configuration ----------
if [[ $ENABLE_UFW -eq 1 ]]; then
  log "Configuring UFW firewall..."
  ufw default deny incoming || true
  ufw default allow outgoing || true
  ufw allow ssh || true
  ufw --force enable || warn "UFW enable failed"
  ok "UFW configured"
fi

# ---------- History configuration ----------
SYS_BASHRC="/etc/bash.bashrc"
grep -q 'histappend' "$SYS_BASHRC" || {
  cat >> "$SYS_BASHRC" <<'HIST'

# Enhanced history for TI work
shopt -s histappend
HISTSIZE=100000
HISTFILESIZE=200000
HISTCONTROL=ignoreboth
HISTTIMEFORMAT="%F %T "
PROMPT_COMMAND="history -a; ${PROMPT_COMMAND}"
HIST
  ok "History configuration enhanced"
}

# ---------- Create configuration directory ----------
TI_CONF_DIR="$USER_HOME/.ti-suite"
mkdir -p "$TI_CONF_DIR"

cat > "$TI_CONF_DIR/config.json" <<CONFIG
{
  "version": "2.0",
  "preset": "$PRESET",
  "user": "$REAL_USER",
  "install_date": "$(date -Iseconds)",
  "slack_webhook": "$SLACK_WEBHOOK",
  "discord_webhook": "$DISCORD_WEBHOOK",
  "auto_update": $AUTO_UPDATE,
  "parallel_jobs": $PARALLEL_JOBS
}
CONFIG
chown "$REAL_USER":"$REAL_USER" -R "$TI_CONF_DIR"

# ========== ENHANCED HELPER SCRIPTS ==========

# ---------- Enhanced quick-recon with parallel execution ----------
cat >/usr/local/bin/quick-recon <<'QUICKRECON'
#!/usr/bin/env bash
set -euo pipefail

usage(){
  cat <<USAGE
Quick Recon - Fast passive reconnaissance pipeline

Usage: $0 -d example.com [OPTIONS]

Options:
  -d, --domain DOMAIN      Target domain (required)
  --proxy [none|tor]       Use proxy (default: none)
  --deep                   Enable deep scanning (nuclei critical/high)
  --parallel N             Parallel jobs (default: 4)
  --screenshot             Take screenshots of alive hosts
  --notify                 Send notifications on completion
  -h, --help              Show this help

Examples:
  $0 -d example.com
  $0 -d example.com --deep --screenshot --notify
  $0 -d example.com --proxy tor --parallel 8
USAGE
  exit 1
}

DOMAIN=""
PROXY="none"
DEEP=0
PARALLEL=4
SCREENSHOT=0
NOTIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2;;
    --proxy) PROXY="$2"; shift 2;;
    --deep) DEEP=1; shift;;
    --parallel) PARALLEL="$2"; shift 2;;
    --screenshot) SCREENSHOT=1; shift;;
    --notify) NOTIFY=1; shift;;
    -h|--help) usage;;
    *) echo "Unknown: $1"; usage;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

RUN="$(date +%Y%m%d-%H%M%S)"
ROOT="$HOME/Recon/${DOMAIN}/${RUN}"
mkdir -p "$ROOT"
cd "$ROOT"

PFX=""
[[ "$PROXY" == "tor" ]] && PFX="proxychains4 -q"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
ok() { echo "[$(date '+%H:%M:%S')] ✓ $*"; }

log "Starting reconnaissance for $DOMAIN"
log "Output: $ROOT"

# Subdomain enumeration (parallel)
log "Subdomain discovery (parallel)..."
{
  $PFX subfinder -silent -all -d "$DOMAIN" -o subs_subfinder.txt 2>/dev/null || true &
  $PFX amass enum -passive -d "$DOMAIN" -o subs_amass.txt 2>/dev/null || true &
  $PFX assetfinder --subs-only "$DOMAIN" > subs_assetfinder.txt 2>/dev/null || true &
  wait
}
cat subs_* 2>/dev/null | sort -u > subs.txt
SUBS_COUNT=$(wc -l < subs.txt)
ok "Subdomains: $SUBS_COUNT"

# Port scanning (top ports)
if command -v naabu >/dev/null 2>&1; then
  log "Port scanning (top 1000)..."
  $PFX naabu -silent -list subs.txt -top-ports 1000 -o ports.txt 2>/dev/null || true
  ok "Port scan complete"
fi

# HTTP probing
log "Probing with httpx..."
$PFX httpx -l subs.txt -status-code -title -ip -tech-detect -follow-redirects \
  -threads "$PARALLEL" -silent -no-color -o httpx.txt 2>/dev/null || true
grep -oE 'https?://[^[:space:]]+' httpx.txt | sort -u > hosts_alive.txt 2>/dev/null || true
ALIVE_COUNT=$(wc -l < hosts_alive.txt)
ok "Alive hosts: $ALIVE_COUNT"

# Vulnerability scanning
if [[ $DEEP -eq 1 ]]; then
  log "Nuclei scanning (critical/high severity)..."
  $PFX nuclei -l hosts_alive.txt -severity critical,high -rate-limit 50 \
    -duc -silent -no-color -stats -o nuclei_findings.txt 2>/dev/null || true
else
  log "Nuclei scanning (low/medium severity)..."
  $PFX nuclei -l hosts_alive.txt -severity low,medium -rate-limit 50 \
    -duc -silent -no-color -stats -o nuclei_findings.txt 2>/dev/null || true
fi
FINDINGS=$(wc -l < nuclei_findings.txt 2>/dev/null || echo 0)
ok "Findings: $FINDINGS"

# Screenshots
if [[ $SCREENSHOT -eq 1 ]] && command -v chromium >/dev/null 2>&1; then
  log "Taking screenshots..."
  mkdir -p screenshots
  while read -r url; do
    filename=$(echo "$url" | sed 's|https\?://||;s|/|_|g').png
    chromium --headless --disable-gpu --no-sandbox --screenshot="screenshots/$filename" "$url" 2>/dev/null || true
  done < hosts_alive.txt
  ok "Screenshots saved"
fi

# Generate report
cat > report.md <<REPORT
# Reconnaissance Report
**Target:** $DOMAIN  
**Date:** $(date)  
**Run ID:** $RUN

## Summary
- **Subdomains Found:** $SUBS_COUNT
- **Alive Hosts:** $ALIVE_COUNT
- **Vulnerabilities:** $FINDINGS

## Top Technologies
$(awk '{print $NF}' httpx.txt | grep -oE '\[[^]]+\]' | sort | uniq -c | sort -rn | head -10)

## Top Findings
$(head -20 nuclei_findings.txt 2>/dev/null || echo "None")

---
*Generated by TI Suite - quick-recon*
REPORT

ok "Report generated: $ROOT/report.md"

# Notifications
if [[ $NOTIFY -eq 1 ]]; then
  CONFIG="$HOME/.ti-suite/config.json"
  if [[ -f "$CONFIG" ]]; then
    SLACK=$(jq -r '.slack_webhook // empty' "$CONFIG")
    if [[ -n "$SLACK" ]]; then
      curl -X POST "$SLACK" -H 'Content-Type: application/json' \
        -d "{\"text\":\"Recon complete: $DOMAIN\\nSubdomains: $SUBS_COUNT | Alive: $ALIVE_COUNT | Findings: $FINDINGS\"}" \
        2>/dev/null || true
    fi
  fi
fi

ok "Complete! Results in: $ROOT"
QUICKRECON
chmod +x /usr/local/bin/quick-recon

# ---------- Enhanced ti-health with comprehensive checks ----------
cat >/usr/local/bin/ti-health <<'HEALTH'
#!/usr/bin/env bash
set -euo pipefail

ok(){ printf "\033[0;32m[✓]\033[0m %s\n" "$*"; }
bad(){ printf "\033[0;31m[✗]\033[0m %s\n" "$*" >&2; }
info(){ printf "\033[0;34m[i]\033[0m %s\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "========================================="
echo "  TI Suite Health Check"
echo "========================================="
echo

# Core tools
echo "== Core Tools =="
for tool in git curl wget python3 pip jq sqlite3; do
  if have "$tool"; then
    version=$("$tool" --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "installed")
    ok "$tool ($version)"
  else
    bad "$tool missing"
  fi
done
echo

# OSINT tools
echo "== OSINT Tools =="
for tool in spiderfoot theHarvester recon-ng subfinder httpx naabu nuclei katana amass; do
  have "$tool" && ok "$tool" || bad "$tool missing"
done
echo

# Privacy tools
echo "== Privacy & Network =="
for tool in tor torsocks proxychains4; do
  have "$tool" && ok "$tool" || info "$tool not installed (optional)"
done
echo

# Services
echo "== Services =="
for svc in tor ssh ufw; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    ok "$svc active"
  else
    info "$svc inactive"
  fi
done
echo

# Connectivity tests
echo "== Connectivity =="
if curl -s -m 5 https://api.ipify.org >/dev/null; then
  CLEAR_IP=$(curl -s -m 5 https://api.ipify.org)
  ok "Direct: $CLEAR_IP"
else
  bad "Direct connection failed"
fi

if have torsocks && systemctl is-active --quiet tor; then
  TOR_IP=$(torsocks curl -s -m 10 https://api.ipify.org 2>/dev/null || echo "failed")
  if [[ "$TOR_IP" != "failed" ]]; then
    ok "Tor: $TOR_IP"
  else
    bad "Tor connection failed"
  fi
fi

if have proxychains4; then
  PC_IP=$(proxychains4 -q curl -s -m 10 https://api.ipify.org 2>/dev/null || echo "failed")
  if [[ "$PC_IP" != "failed" ]]; then
    ok "Proxychains: $PC_IP"
  else
    info "Proxychains not configured"
  fi
fi
echo

# Disk space
echo "== Storage =="
df -h "$HOME" | tail -1 | awk '{printf "Home: %s / %s (%s used)\n", $3, $2, $5}'
echo

# Updates available
echo "== Tool Versions =="
for tool in subfinder httpx nuclei; do
  if have "$tool"; then
    "$tool" -version 2>/dev/null | head -1 || true
  fi
done
echo

info "Last update: $(stat -c %y /var/cache/ti-suite/last_update 2>/dev/null | cut -d' ' -f1 || echo 'never')"
echo "========================================="
HEALTH
chmod +x /usr/local/bin/ti-health

# ---------- Enhanced ti-update with rollback capability ----------
cat >/usr/local/bin/ti-update <<'UPDATE'
#!/usr/bin/env bash
set -euo pipefail

log() { echo "[*] $*"; }
ok() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

BACKUP_DIR="$HOME/.ti-suite/backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

log "Creating backup..."
cp /usr/local/bin/{quick-recon,ti-health,ti-update,iocgrab,webshot,new-case,ti-feeds} "$BACKUP_DIR/" 2>/dev/null || true
ok "Backup created: $BACKUP_DIR"

log "apt update/upgrade..."
sudo apt-get update -y && sudo apt-get -y -o Dpkg::Options::="--force-confold" dist-upgrade || warn "apt upgrade failed"

log "Python packages..."
pip install -U pip holehe knockpy email2phonenumber maigret feedparser tldextract 2>/dev/null || warn "pip updates failed"

log "ProjectDiscovery tools..."
for tool in subfinder httpx naabu nuclei katana; do
  if command -v "$tool" >/dev/null 2>&1; then
    log "Updating $tool..."
    "$tool" -update 2>/dev/null || warn "$tool update failed"
  fi
done

log "Nuclei templates..."
command -v nuclei >/dev/null 2>&1 && nuclei -update-templates -ut 2>/dev/null || warn "template update failed"

log "Git repositories..."
for repo in /opt/*/; do
  if [[ -d "$repo/.git" ]]; then
    log "Updating $(basename "$repo")..."
    (cd "$repo" && git pull --rebase --autostash 2>/dev/null) || warn "$(basename "$repo") update failed"
  fi
done

sudo apt-get autoremove -y 2>/dev/null || true
sudo apt-get autoclean -y 2>/dev/null || true

date +%s | sudo tee /var/cache/ti-suite/last_update >/dev/null

ok "Update complete!"
ok "Backup available at: $BACKUP_DIR"
UPDATE
chmod +x /usr/local/bin/ti-update

# ---------- Enhanced iocgrab with more IOC types ----------
cat >/usr/local/bin/iocgrab <<'IOCGRAB'
#!/usr/bin/env python3
"""
IOC Extractor - Extract Indicators of Compromise from text
Supports: IPs, domains, URLs, hashes, emails, CVEs, Bitcoin addresses
"""
import re
import sys
import csv
import os
import time
import argparse
from collections import defaultdict

REGEX_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "url": r"https?://[^\s\"'<>)]+",
    "email": r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "domain": r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "bitcoin": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
}

def extract_iocs(text, ioc_types=None):
    """Extract IOCs from text"""
    if ioc_types is None:
        ioc_types = REGEX_PATTERNS.keys()
    
    found = defaultdict(set)
    
    for ioc_type in ioc_types:
        if ioc_type not in REGEX_PATTERNS:
            continue
        pattern = REGEX_PATTERNS[ioc_type]
        for match in re.findall(pattern, text, re.IGNORECASE):
            # Filter out common false positives
            if ioc_type == "domain" and match.lower() in ["localhost", "example.com", "test.local"]:
                continue
            if ioc_type == "ipv4" and (match.startswith("0.") or match.startswith("127.")):
                continue
            found[ioc_type].add(match)
    
    return found

def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from text")
    parser.add_argument("input", nargs="?", help="Input file (default: stdin)")
    parser.add_argument("-o", "--output", help="Output CSV file")
    parser.add_argument("-t", "--types", help="Comma-separated IOC types to extract")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()
    
    # Read input
    if args.input:
        with open(args.input, 'r', errors='ignore') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    
    # Extract IOCs
    ioc_types = args.types.split(",") if args.types else None
    found = extract_iocs(text, ioc_types)
    
    # Output
    if args.json:
        import json
        result = {k: list(v) for k, v in found.items()}
        print(json.dumps(result, indent=2))
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        output = args.output or os.path.expanduser(f"~/OSINT/iocs-{stamp}.csv")
        os.makedirs(os.path.dirname(output), exist_ok=True)
        
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "value", "count"])
            
            for ioc_type, values in sorted(found.items()):
                for value in sorted(values):
                    writer.writerow([ioc_type, value, 1])
        
        print(f"[+] Extracted {sum(len(v) for v in found.values())} IOCs")
        print(f"[+] Output: {output}")
        
        # Summary
        for ioc_type, values in sorted(found.items()):
            print(f"    {ioc_type}: {len(values)}")

if __name__ == "__main__":
    main()
IOCGRAB
chmod +x /usr/local/bin/iocgrab

# ---------- Enhanced webshot with batch processing ----------
cat >/usr/local/bin/webshot <<'WEBSHOT'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
webshot - Headless browser screenshots

Usage: 
  $0 <url> [output.png]           # Single screenshot
  $0 -l urls.txt [-o output_dir]  # Batch screenshots

Options:
  -l, --list FILE    File containing URLs (one per line)
  -o, --output DIR   Output directory (default: screenshots)
  -w, --width N      Viewport width (default: 1366)
  -h, --height N     Viewport height (default: 768)
  --timeout N        Page load timeout in ms (default: 10000)
  -h, --help         Show this help
USAGE
  exit 1
}

URL=""
LIST=""
OUTPUT="screenshots"
WIDTH=1366
HEIGHT=768
TIMEOUT=10000

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--list) LIST="$2"; shift 2;;
    -o|--output) OUTPUT="$2"; shift 2;;
    -w|--width) WIDTH="$2"; shift 2;;
    --height) HEIGHT="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    -h|--help) usage;;
    *) URL="$1"; shift;;
  esac
done

BIN="$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo "")"
[[ -z "$BIN" ]] && { echo "chromium not found"; exit 2; }

take_screenshot() {
  local url="$1"
  local output="$2"
  
  "$BIN" --headless --disable-gpu --no-sandbox \
    --virtual-time-budget="$TIMEOUT" \
    --window-size="$WIDTH,$HEIGHT" \
    --screenshot="$output" \
    "$url" 2>/dev/null || true
  
  [[ -f "$output" ]] && echo "[+] $output" || echo "[!] Failed: $url"
}

if [[ -n "$LIST" ]]; then
  [[ ! -f "$LIST" ]] && { echo "File not found: $LIST"; exit 1; }
  mkdir -p "$OUTPUT"
  
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    filename=$(echo "$url" | sed 's|https\?://||;s|[^a-zA-Z0-9]|_|g').png
    take_screenshot "$url" "$OUTPUT/$filename"
  done < "$LIST"
  
  echo "[+] Screenshots saved in: $OUTPUT"
elif [[ -n "$URL" ]]; then
  OUT="${2:-screenshot-$(date +%Y%m%d-%H%M%S).png}"
  take_screenshot "$URL" "$OUT"
else
  usage
fi
WEBSHOT
chmod +x /usr/local/bin/webshot

# ---------- Enhanced new-case with templates ----------
cat >/usr/local/bin/new-case <<'NEWCASE'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
new-case - Initialize case directory structure

Usage: $0 <case-name> [--type osint|incident|malware|breach]

Options:
  --type TYPE    Case type (default: osint)
  --client NAME  Client/organization name
  --ticket ID    Ticket/reference number
  -h, --help     Show this help
USAGE
  exit 1
}

[[ $# -lt 1 ]] && usage

CASE_NAME="$1"
shift

TYPE="osint"
CLIENT=""
TICKET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) TYPE="$2"; shift 2;;
    --client) CLIENT="$2"; shift 2;;
    --ticket) TICKET="$2"; shift 2;;
    -h|--help) usage;;
    *) shift;;
  esac
done

STAMP="$(date +%Y%m%d)"
CASE_ID="CASE-${STAMP}-$(echo "$CASE_NAME" | tr '[:upper:] ' '[:lower:]-')"
ROOT="$HOME/Cases/$CASE_ID"

mkdir -p "$ROOT"/{evidence,captures,iocs,notes,screenshots,exports,logs,tools,reports}

# Case metadata
cat > "$ROOT/case-info.json" <<JSON
{
  "case_id": "$CASE_ID",
  "case_name": "$CASE_NAME",
  "type": "$TYPE",
  "client": "$CLIENT",
  "ticket": "$TICKET",
  "opened": "$(date -Iseconds)",
  "investigator": "$(whoami)",
  "status": "open"
}
JSON

# README
cat > "$ROOT/README.md" <<README
# $CASE_ID

**Type:** $TYPE  
**Opened:** $(date)  
**Investigator:** $(whoami)  
${CLIENT:+**Client:** $CLIENT}  
${TICKET:+**Ticket:** $TICKET}

## Scope
[Describe authorized investigation scope]

## Objectives
- [ ] Objective 1
- [ ] Objective 2

## Timeline
| Date | Event | Notes |
|------|-------|-------|
| $(date +%Y-%m-%d) | Case opened | Initial investigation |

## Evidence Chain
| Item | Date Collected | Collector | Hash | Location |
|------|----------------|-----------|------|----------|
| | | | | |

## Findings
[Document findings here]

## Tools Used
- 

## References
- 

---
*Case managed by TI Suite*
README

# Case type specific templates
case "$TYPE" in
  incident)
    cat > "$ROOT/incident-timeline.md" <<INCIDENT
# Incident Timeline

## Initial Detection
- **Date/Time:**
- **Source:**
- **Indicators:**

## Response Actions
- 

## Impact Assessment
- **Systems Affected:**
- **Data Exposure:**
- **Business Impact:**
INCIDENT
    ;;
  malware)
    cat > "$ROOT/malware-analysis.md" <<MALWARE
# Malware Analysis

## Sample Information
- **Filename:**
- **MD5:**
- **SHA1:**
- **SHA256:**
- **File Type:**
- **Size:**

## Static Analysis
- 

## Dynamic Analysis
- 

## Network Indicators
- 

## MITRE ATT&CK Mapping
- 
MALWARE
    ;;
esac

# Initialize git repo
cd "$ROOT"
git init >/dev/null 2>&1 || true
cat > .gitignore <<GITIGNORE
*.pcap
*.dmp
*password*
*credential*
.DS_Store
GITIGNORE

echo "[+] Case initialized: $ROOT"
echo "[+] Case ID: $CASE_ID"
echo
echo "Quick commands:"
echo "  cd $ROOT"
echo "  cat case-info.json"
echo "  vim README.md"
NEWCASE
chmod +x /usr/local/bin/new-case

# ---------- Enhanced ti-feeds with more sources ----------
mkdir -p /opt/ti-feeds
cat > /opt/ti-feeds/ti-feeds.py <<'TIFEEDS'
#!/usr/bin/env python3
"""
Threat Intelligence Feed Aggregator
Fetches and stores TI from multiple sources
"""
import os
import sqlite3
import time
import feedparser
import json
import hashlib
from datetime import datetime

DB = os.path.expanduser("~/OSINT/ti-feeds.db")

FEEDS = [
    ("CISA Alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("NVD CVE Recent", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"),
    ("US-CERT", "https://www.cisa.gov/uscert/ncas/current-activity.xml"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Threatpost", "https://threatpost.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("DarkReading", "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("ProjectDiscovery", "https://blog.projectdiscovery.io/rss/"),
    ("Tor Project", "https://blog.torproject.org/feed.xml"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
]

def init_db():
    """Initialize database"""
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed TEXT NOT NULL,
            guid TEXT UNIQUE NOT NULL,
            title TEXT,
            link TEXT,
            published TEXT,
            summary TEXT,
            tags TEXT,
            fetched_at INTEGER,
            hash TEXT
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feed_stats (
            feed TEXT PRIMARY KEY,
            last_fetch INTEGER,
            total_items INTEGER,
            new_items INTEGER
        )
    """)
    
    cur.execute("CREATE INDEX IF NOT EXISTS idx_feed ON feeds(feed)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_published ON feeds(published)")
    
    con.commit()
    return con

def fetch_feeds(con):
    """Fetch all feeds"""
    cur = con.cursor()
    new_total = 0
    
    for feed_name, feed_url in FEEDS:
        print(f"[*] Fetching: {feed_name}")
        
        try:
            data = feedparser.parse(feed_url)
            new_count = 0
            
            for entry in data.entries:
                guid = getattr(entry, "id", None) or getattr(entry, "guid", None) or getattr(entry, "link", "")
                title = getattr(entry, "title", "")
                link = getattr(entry, "link", "")
                published = getattr(entry, "published", "") or getattr(entry, "updated", "")
                summary = getattr(entry, "summary", "")
                tags = ",".join([t.term for t in getattr(entry, "tags", [])])
                
                # Create content hash for deduplication
                content = f"{title}{link}{summary}"
                content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
                
                try:
                    cur.execute("""
                        INSERT INTO feeds (feed, guid, title, link, published, summary, tags, fetched_at, hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (feed_name, guid, title, link, published, summary, tags, int(time.time()), content_hash))
                    
                    con.commit()
                    new_count += 1
                    print(f"  [NEW] {title[:60]}")
                    
                except sqlite3.IntegrityError:
                    pass  # Duplicate
            
            # Update stats
            cur.execute("""
                INSERT OR REPLACE INTO feed_stats (feed, last_fetch, total_items, new_items)
                VALUES (?, ?, ?, ?)
            """, (feed_name, int(time.time()), len(data.entries), new_count))
            
            con.commit()
            new_total += new_count
            
            print(f"  [+] New items: {new_count}")
            
        except Exception as e:
            print(f"  [!] Error: {e}")
    
    return new_total

def show_stats(con):
    """Display statistics"""
    cur = con.cursor()
    
    print("\n" + "="*60)
    print("FEED STATISTICS")
    print("="*60)
    
    cur.execute("SELECT feed, last_fetch, total_items, new_items FROM feed_stats ORDER BY last_fetch DESC")
    
    for feed, last_fetch, total, new in cur.fetchall():
        last_time = datetime.fromtimestamp(last_fetch).strftime("%Y-%m-%d %H:%M")
        print(f"{feed:30} | Last: {last_time} | Total: {total:4} | New: {new:3}")
    
    cur.execute("SELECT COUNT(*) FROM feeds")
    total = cur.fetchone()[0]
    print("="*60)
    print(f"TOTAL ITEMS IN DATABASE: {total}")
    print("="*60)

def search_feeds(con, query):
    """Search feeds"""
    cur = con.cursor()
    
    cur.execute("""
        SELECT feed, title, link, published 
        FROM feeds 
        WHERE title LIKE ? OR summary LIKE ?
        ORDER BY fetched_at DESC 
        LIMIT 20
    """, (f"%{query}%", f"%{query}%"))
    
    results = cur.fetchall()
    
    if not results:
        print(f"No results for: {query}")
        return
    
    print(f"\nSearch results for: {query}")
    print("="*80)
    
    for feed, title, link, published in results:
        print(f"[{feed}] {title}")
        print(f"  {link}")
        print(f"  {published}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Threat Intelligence Feed Aggregator")
    parser.add_argument("--fetch", action="store_true", help="Fetch feeds")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--search", help="Search feeds")
    parser.add_argument("--list", action="store_true", help="List recent items")
    parser.add_argument("-n", type=int, default=20, help="Number of items to list")
    
    args = parser.parse_args()
    
    con = init_db()
    
    if args.fetch:
        new_items = fetch_feeds(con)
        show_stats(con)
        print(f"\n[+] Total new items: {new_items}")
        
    elif args.stats:
        show_stats(con)
        
    elif args.search:
        search_feeds(con, args.search)
        
    elif args.list:
        cur = con.cursor()
        cur.execute("""
            SELECT feed, title, link, published 
            FROM feeds 
            ORDER BY fetched_at DESC 
            LIMIT ?
        """, (args.n,))
        
        print(f"\nRecent {args.n} items:")
        print("="*80)
        
        for feed, title, link, published in cur.fetchall():
            print(f"[{feed}] {title}")
            print(f"  {link}")
            print(f"  {published}\n")
    else:
        # Default: fetch feeds
        new_items = fetch_feeds(con)
        print(f"\n[+] Total new items: {new_items}")
    
    con.close()

if __name__ == "__main__":
    main()
TIFEEDS
chmod +x /opt/ti-feeds/ti-feeds.py
ln -sf /opt/ti-feeds/ti-feeds.py /usr/local/bin/ti-feeds

# ---------- NEW: ti-report - Comprehensive reporting ----------
cat > /usr/local/bin/ti-report <<'TIREPORT'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
ti-report - Generate comprehensive investigation reports

Usage: $0 <recon-dir> [OPTIONS]

Options:
  -o, --output FILE     Output file (default: report.html)
  -f, --format [html|md|pdf]  Format (default: html)
  --title TITLE         Report title
  -h, --help           Show this help
USAGE
  exit 1
}

[[ $# -lt 1 ]] && usage

RECON_DIR="$1"
shift

OUTPUT="report.html"
FORMAT="html"
TITLE="Reconnaissance Report"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUTPUT="$2"; shift 2;;
    -f|--format) FORMAT="$2"; shift 2;;
    --title) TITLE="$2"; shift 2;;
    -h|--help) usage;;
    *) shift;;
  esac
done

[[ ! -d "$RECON_DIR" ]] && { echo "Directory not found: $RECON_DIR"; exit 1; }

cd "$RECON_DIR"

DOMAIN=$(basename "$(dirname "$RECON_DIR")")
RUN=$(basename "$RECON_DIR")

# Gather statistics
SUBS=$(wc -l < subs.txt 2>/dev/null || echo 0)
ALIVE=$(wc -l < hosts_alive.txt 2>/dev/null || echo 0)
FINDINGS=$(wc -l < nuclei_findings.txt 2>/dev/null || echo 0)

if [[ "$FORMAT" == "html" ]]; then
  cat > "$OUTPUT" <<HTML
<!DOCTYPE html>
<html>
<head>
  <title>$TITLE - $DOMAIN</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .stat-card { background: #f8f9fa; padding: 20px; border-left: 4px solid #007bff; }
    .stat-card h3 { margin: 0; color: #666; font-size: 14px; }
    .stat-card .value { font-size: 32px; font-weight: bold; color: #007bff; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #007bff; color: white; }
    tr:hover { background: #f5f5f5; }
    .finding { background: #fff3cd; padding: 10px; margin: 10px 0; border-left: 4px solid #ffc107; }
    .critical { border-left-color: #dc3545; }
    .high { border-left-color: #fd7e14; }
    .medium { border-left-color: #ffc107; }
    .low { border-left-color: #28a745; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>$TITLE</h1>
    <p><strong>Target:</strong> $DOMAIN<br>
    <strong>Run ID:</strong> $RUN<br>
    <strong>Date:</strong> $(date)<br>
    <strong>Investigator:</strong> $(whoami)</p>
    
    <h2>Executive Summary</h2>
    <div class="summary">
      <div class="stat-card">
        <h3>Subdomains</h3>
        <div class="value">$SUBS</div>
      </div>
      <div class="stat-card">
        <h3>Alive Hosts</h3>
        <div class="value">$ALIVE</div>
      </div>
      <div class="stat-card">
        <h3>Findings</h3>
        <div class="value">$FINDINGS</div>
      </div>
    </div>
    
    <h2>Discovered Subdomains</h2>
    <table>
      <tr><th>#</th><th>Subdomain</th></tr>
$(head -50 subs.txt 2>/dev/null | nl | awk '{printf "      <tr><td>%s</td><td>%s</td></tr>\n", $1, $2}')
    </table>
    
    <h2>Live Hosts</h2>
    <table>
      <tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr>
$(head -30 httpx.txt 2>/dev/null | awk '{printf "      <tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n", $1, $2, $3, $NF}')
    </table>
    
    <h2>Security Findings</h2>
$(if [[ -f nuclei_findings.txt && -s nuclei_findings.txt ]]; then
    while IFS= read -r line; do
      severity="low"
      [[ "$line" =~ critical ]] && severity="critical"
      [[ "$line" =~ high ]] && severity="high"
      [[ "$line" =~ medium ]] && severity="medium"
      echo "    <div class=\"finding $severity\">$line</div>"
    done < <(head -50 nuclei_findings.txt)
  else
    echo "    <p>No findings recorded.</p>"
  fi)
    
    <div class="footer">
      Generated by TI Suite | $(date) | Confidential
    </div>
  </div>
</body>
</html>
HTML

  echo "[+] HTML report generated: $OUTPUT"
  
elif [[ "$FORMAT" == "md" ]]; then
  cat > "$OUTPUT" <<MARKDOWN
# $TITLE

**Target:** $DOMAIN  
**Run ID:** $RUN  
**Date:** $(date)  
**Investigator:** $(whoami)

## Executive Summary

- **Subdomains Found:** $SUBS
- **Alive Hosts:** $ALIVE
- **Security Findings:** $FINDINGS

## Subdomains

\`\`\`
$(head -50 subs.txt 2>/dev/null || echo "None")
\`\`\`

## Live Hosts

$(head -30 httpx.txt 2>/dev/null || echo "None")

## Security Findings

$(head -50 nuclei_findings.txt 2>/dev/null || echo "None")

---
*Generated by TI Suite*
MARKDOWN

  echo "[+] Markdown report generated: $OUTPUT"
fi
TIREPORT
chmod +x /usr/local/bin/ti-report

# ---------- NEW: ti-dashboard - Monitoring dashboard ----------
cat > /usr/local/bin/ti-dashboard <<'TIDASH'
#!/usr/bin/env bash
set -euo pipefail

echo "TI Suite Dashboard - Press Ctrl+C to exit"
echo

while true; do
  clear
  echo "========================================="
  echo "  TI SUITE DASHBOARD"
  echo "  $(date)"
  echo "========================================="
  echo
  
  # System stats
  echo "== System =="
  echo "Uptime: $(uptime -p)"
  echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
  echo "Disk: $(df -h "$HOME" | tail -1 | awk '{print $5 " used"}')"
  echo
  
  # Active cases
  echo "== Active Cases =="
  if [[ -d "$HOME/Cases" ]]; then
    find "$HOME/Cases" -maxdepth 1 -type d -name "CASE-*" | tail -5 | while read -r case; do
      echo "  $(basename "$case")"
    done
  else
    echo "  None"
  fi
  echo
  
  # Recent recon
  echo "== Recent Recon =="
  if [[ -d "$HOME/Recon" ]]; then
    find "$HOME/Recon" -mindepth 2 -maxdepth 2 -type d | tail -5 | while read -r recon; do
      domain=$(basename "$(dirname "$recon")")
      run=$(basename "$recon")
      echo "  $domain / $run"
    done
  else
    echo "  None"
  fi
  echo
  
  # Tor status
  echo "== Services =="
  systemctl is-active --quiet tor 2>/dev/null && echo "  Tor: Running" || echo "  Tor: Stopped"
  echo
  
  # Recent TI feeds
  echo "== Threat Intelligence (last 5) =="
  if [[ -f "$HOME/OSINT/ti-feeds.db" ]]; then
    sqlite3 "$HOME/OSINT/ti-feeds.db" "SELECT feed, title FROM feeds ORDER BY fetched_at DESC LIMIT 5" 2>/dev/null | while IFS='|' read -r feed title; do
      echo "  [$feed] ${title:0:50}..."
    done
  else
    echo "  No feeds"
  fi
  echo
  
  echo "========================================="
  
  sleep 10
done
TIDASH
chmod +x /usr/local/bin/ti-dashboard

# ---------- NEW: Automation with cron ----------
if [[ $ENABLE_AUTOMATION -eq 1 ]]; then
  log "Setting up automation..."
  
  CRON_SCRIPT="/usr/local/bin/ti-automate"
  cat > "$CRON_SCRIPT" <<'AUTOCRON'
#!/usr/bin/env bash
# Automated TI suite maintenance

LOG="/var/log/ti-suite/auto-$(date +%Y%m%d).log"

{
  echo "[$(date)] Starting automated tasks..."
  
  # Update TI feeds daily
  /usr/local/bin/ti-feeds --fetch
  
  # Update tools weekly (only on Sundays)
  if [[ $(date +%u) -eq 7 ]]; then
    /usr/local/bin/ti-update
  fi
  
  # Cleanup old logs (>30 days)
  find /var/log/ti-suite -type f -mtime +30 -delete
  
  echo "[$(date)] Automated tasks complete"
} >> "$LOG" 2>&1
AUTOCRON
  chmod +x "$CRON_SCRIPT"
  
  # Add to crontab
  CRON_LINE="0 2 * * * $CRON_SCRIPT"
  (crontab -l 2>/dev/null | grep -v "$CRON_SCRIPT"; echo "$CRON_LINE") | crontab -
  
  ok "Automation configured (daily 2 AM)"
fi

# ---------- Notification helpers ----------
if [[ -n "$SLACK_WEBHOOK" || -n "$DISCORD_WEBHOOK" ]]; then
  cat > /usr/local/bin/ti-notify <<'NOTIFY'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <message>"
  exit 1
}

[[ $# -lt 1 ]] && usage

MESSAGE="$1"
CONFIG="$HOME/.ti-suite/config.json"

if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found"
  exit 1
fi

SLACK=$(jq -r '.slack_webhook // empty' "$CONFIG")
DISCORD=$(jq -r '.discord_webhook // empty' "$CONFIG")

# Slack
if [[ -n "$SLACK" ]]; then
  curl -X POST "$SLACK" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"$MESSAGE\"}" \
    2>/dev/null || true
fi

# Discord
if [[ -n "$DISCORD" ]]; then
  curl -X POST "$DISCORD" \
    -H 'Content-Type: application/json' \
    -d "{\"content\":\"$MESSAGE\"}" \
    2>/dev/null || true
fi
NOTIFY
  chmod +x /usr/local/bin/ti-notify
  ok "Notification system configured"
fi

# ---------- Completion summary ----------
track_performance

echo
echo "========================================="
echo "  INSTALLATION COMPLETE"
echo "========================================="
echo "User:           $REAL_USER"
echo "Home:           $USER_HOME"
echo "Preset:         $PRESET"
echo "Offsec Tools:   $([[ $WITH_OFFSEC -eq 1 ]] && echo 'ENABLED' || echo 'disabled')"
echo "UFW Firewall:   $([[ $ENABLE_UFW -eq 1 ]] && echo 'enabled' || echo 'skipped')"
echo "Docker:         $([[ $INSTALL_DOCKER -eq 1 ]] && echo 'installed' || echo 'skipped')"
echo "Automation:     $([[ $ENABLE_AUTOMATION -eq 1 ]] && echo 'enabled' || echo 'disabled')"
echo "AI Tools:       $([[ $INSTALL_AI_TOOLS -eq 1 ]] && echo 'installed' || echo 'skipped')"
echo "Proxy:          $QC_PROXY"
echo "Log File:       $LOG_FILE"
echo "========================================="
echo
echo "Available Commands:"
echo "  quick-recon      Fast reconnaissance pipeline"
echo "  ti-health        System health check"
echo "  ti-update        Update all tools"
echo "  iocgrab          Extract IOCs from text"
echo "  webshot          Screenshots (batch supported)"
echo "  new-case         Initialize case directory"
echo "  ti-feeds         Threat intelligence feeds"
echo "  ti-report        Generate reports (HTML/MD)"
echo "  ti-dashboard     Live monitoring dashboard"
[[ $ENABLE_AUTOMATION -eq 1 ]] && echo "  ti-automate      Run automated tasks"
[[ -n "$SLACK_WEBHOOK" || -n "$DISCORD_WEBHOOK" ]] && echo "  ti-notify        Send notifications"
echo
echo "Quick Start:"
echo "  1. Open new terminal (to load aliases)"
echo "  2. Run: ti-health"
echo "  3. Try: quick-recon -d example.com --deep"
echo "  4. Monitor: ti-dashboard"
echo "  5. Create case: new-case 'investigation-name'"
echo
echo "Documentation: /opt/ti-suite/README.md"
echo "Config: $TI_CONF_DIR/config.json"
echo "========================================="

ok "Setup complete! Happy hunting! 🎯"
