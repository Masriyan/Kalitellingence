#!/usr/bin/env bash
# kali-ti-suite.sh
# Unified, idempotent installer for Threat Intel / OSINT / Dark-web workflows on Kali
# Presets, health checks, auto-updates, helper pipelines & evidence utilities.
# For authorized investigations only.

set -u  # keep control flow; we'll handle failures explicitly
export DEBIAN_FRONTEND=noninteractive

# ---------- logging ----------
log()  { printf "[*] %s\n" "$*"; }
ok()   { printf "[+] %s\n" "$*"; }
warn() { printf "[!] %s\n" "$*" >&2; }
die()  { printf "[x] %s\n" "$*" >&2; exit 1; }

# ---------- require root ----------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "Run as root (e.g., sudo $0)"
fi

# ---------- real user & home ----------
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  REAL_USER="${SUDO_USER}"
else
  REAL_USER="$(logname 2>/dev/null || echo root)"
fi
USER_HOME="$(eval echo ~${REAL_USER})"

# ---------- args / presets ----------
PRESET="passive"      # passive | darkweb | easm | dfir | full
WITH_OFFSEC=0         # hashcat, hydra, john, cupp
ENABLE_UFW=1
QC_PROXY="none"       # none | tor

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset) PRESET="${2:-}"; shift 2;;
    --with-offsec) WITH_OFFSEC=1; shift;;
    --no-ufw) ENABLE_UFW=0; shift;;
    --proxy) QC_PROXY="${2:-}"; shift 2;;
    -h|--help)
      cat <<USAGE
Usage: sudo $0 [--preset passive|darkweb|easm|dfir|full] [--with-offsec] [--no-ufw] [--proxy none|tor]
Default preset: passive (safe OSINT)
Installs helper commands: quick-recon, ti-health, ti-update, iocgrab, webshot, new-case, ti-feeds
USAGE
      exit 0;;
    *) warn "Unknown arg: $1"; shift;;
  done
done

case "$PRESET" in
  passive|darkweb|easm|dfir|full) ;;
  *) warn "Unknown preset '$PRESET', falling back to 'passive'"; PRESET="passive";;
esac

# ---------- apt helpers ----------
APT_NEEDS_UPDATE=1
apt_update_once() {
  if [[ $APT_NEEDS_UPDATE -eq 1 ]]; then
    log "apt update…"; apt-get update -y || die "apt update failed"
    APT_NEEDS_UPDATE=0
  fi
}
apt_install() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then return 0; fi
  apt_update_once
  if ! apt-get install -y "$pkg"; then warn "apt install failed: $pkg"; return 1; fi
}

# ---------- base stacks ----------
BASE_PKGS=(
  git curl wget ca-certificates gnupg lsb-release jq whois dnsutils
  python3 python3-pip python3-venv python3-dev build-essential libssl-dev libffi-dev
  sqlite3 chromium  # headless screenshots
)

NET_PRIVACY_PKGS=( tor torsocks proxychains4 openvpn torbrowser-launcher onionshare-cli )

OSINT_PKGS=( spiderfoot theharvester recon-ng sublist3r sn0int dnstwist
             exiftool metagoofil seclists )

PDISCOVERY_PKGS=( subfinder httpx-toolkit naabu nuclei katana amass nmap masscan )

DFIR_PKGS=( yara binwalk foremost )

OFFSEC_PKGS=( hashcat john hydra cupp )

# ---------- choose sets by preset ----------
APT_LIST=( "${BASE_PKGS[@]}" )
case "$PRESET" in
  passive)   APT_LIST+=( "${OSINT_PKGS[@]}" "${PDISCOVERY_PKGS[@]}" );;
  darkweb)   APT_LIST+=( "${OSINT_PKGS[@]}" "${NET_PRIVACY_PKGS[@]}" );;
  easm)      APT_LIST+=( "${PDISCOVERY_PKGS[@]}" );;
  dfir)      APT_LIST+=( "${DFIR_PKGS[@]}" "${OSINT_PKGS[@]}" );;
  full)      APT_LIST+=( "${BASE_PKGS[@]}" "${NET_PRIVACY_PKGS[@]}" "${OSINT_PKGS[@]}" "${PDISCOVERY_PKGS[@]}" "${DFIR_PKGS[@]}" );;
esac
[[ $WITH_OFFSEC -eq 1 ]] && APT_LIST+=( "${OFFSEC_PKGS[@]}" )

# ---------- pip toolchain ----------
PIP_LIST=( holehe knockpy email2phonenumber maigret feedparser tldextract )
[[ "$PRESET" == "dfir" || "$PRESET" == "full" ]] && PIP_LIST+=( volatility3 )

# ---------- git tools ----------
GIT_TOOLS=( "https://github.com/DedSecInside/TorBot.git /opt/TorBot /usr/local/bin/torbot" )

# ---------- system upgrade ----------
log "Full system upgrade (safe keep conf)…"
apt_update_once
apt-get -y -o Dpkg::Options::="--force-confold" dist-upgrade || warn "dist-upgrade had issues"

# ---------- install apt packages ----------
log "Installing packages for preset: $PRESET"
for p in "${APT_LIST[@]}"; do
  apt_install "$p" || true
done

# ---------- pip installs ----------
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
for p in "${PIP_LIST[@]}"; do
  if python3 -m pip show "$p" >/dev/null 2>&1; then
    :
  else
    python3 -m pip install "$p" || warn "pip install failed: $p"
  fi
done

# ---------- clone repos ----------
clone_or_pull() {
  local repo="$1" dest="$2"
  if [[ -d "$dest/.git" ]]; then
    (cd "$dest" && git pull --rebase --autostash || true)
  else
    git clone --depth 1 "$repo" "$dest" || warn "clone failed: $repo"
  fi
}
safe_symlink() {
  local src="$1" link="$2"
  [[ -e "$src" ]] || { warn "missing $src"; return; }
  ln -sf "$src" "$link" && chmod +x "$link"
}
for triple in "${GIT_TOOLS[@]}"; do
  read -r repo dest link <<<"$triple"
  clone_or_pull "$repo" "$dest"
  [[ -f "$dest/requirements.txt" ]] && python3 -m pip install -r "$dest/requirements.txt" || true
  if [[ -n "${link:-}" ]]; then
    if   [[ -f "$dest/main.py" ]]; then safe_symlink "$dest/main.py" "$link"
    elif [[ -f "$dest/torbot.py" ]]; then safe_symlink "$dest/torbot.py" "$link"
    fi
  fi
done

# ---------- proxychains config (if present) ----------
PC_CONF="/etc/proxychains4.conf"
[[ -f "$PC_CONF" ]] || PC_CONF="/etc/proxychains.conf"
if [[ -f "$PC_CONF" ]]; then
  sed -i 's/^\s*#\?\s*dynamic_chain.*/dynamic_chain/' "$PC_CONF" || true
  sed -i 's/^\s*strict_chain/#strict_chain/' "$PC_CONF" || true
  grep -Eq '^\s*proxy_dns' "$PC_CONF" || echo "proxy_dns" >> "$PC_CONF"
  grep -Eq '^\s*socks5\s+127\.0\.0\.1\s+9050' "$PC_CONF" || echo "socks5 127.0.0.1 9050" >> "$PC_CONF"
  ok "ProxyChains configured: $PC_CONF"
fi

# ---------- services ----------
systemctl enable tor 2>/dev/null || true
systemctl enable openvpn 2>/dev/null || true

# ---------- workspaces ----------
mkdir -p "$USER_HOME/OSINT" "$USER_HOME/DarkWeb" "$USER_HOME/Recon" \
         "$USER_HOME/Passwords" "$USER_HOME/Metadata" "$USER_HOME/SocialMedia" \
         "$USER_HOME/Logs" "$USER_HOME/Cases"
chown -R "$REAL_USER":"$REAL_USER" "$USER_HOME/OSINT" "$USER_HOME/DarkWeb" "$USER_HOME/Recon" \
  "$USER_HOME/Passwords" "$USER_HOME/Metadata" "$USER_HOME/SocialMedia" "$USER_HOME/Logs" "$USER_HOME/Cases"

# ---------- aliases ----------
ensure_line_in_file() { local line="$1" file="$2"; touch "$file"; grep -Fqx "$line" "$file" || echo "$line" >> "$file"; }
BRC="$USER_HOME/.bashrc"; touch "$BRC"
ensure_line_in_file "alias sf='spiderfoot -l 127.0.0.1:5001'" "$BRC"
ensure_line_in_file "alias recon='recon-ng'" "$BRC"
ensure_line_in_file "alias th='theHarvester'" "$BRC"
ensure_line_in_file "alias pc='proxychains4'" "$BRC"
ensure_line_in_file "alias subf=\"subfinder -silent -all\"" "$BRC"
ensure_line_in_file "alias httpx='httpx -silent -status-code -ip -title -follow-redirects'" "$BRC"
ensure_line_in_file "alias nuclei='nuclei -duc -stats'" "$BRC"
chown "$REAL_USER":"$REAL_USER" "$BRC"

# ---------- firewall ----------
if [[ $ENABLE_UFW -eq 1 ]]; then
  ufw default deny incoming || true
  ufw default allow outgoing || true
  ufw --force enable || warn "UFW enable failed"
fi

# ---------- persistent history ----------
SYS_BASHRC="/etc/bash.bashrc"
ensure_line_in_file "shopt -s histappend" "$SYS_BASHRC"
grep -q 'history -a' "$SYS_BASHRC" || echo 'PROMPT_COMMAND="history -a; ${PROMPT_COMMAND}"' >> "$SYS_BASHRC"

# ---------- helper: quick-recon ----------
cat >/usr/local/bin/quick-recon <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
usage(){ echo "Usage: $0 -d example.com [--proxy none|tor]"; exit 1; }
DOMAIN=""; PROXY="none"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2;;
    --proxy) PROXY="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown: $1"; usage;;
  esac
done
[[ -z "$DOMAIN" ]] && usage
RUN="$(date +%Y%m%d-%H%M%S)"
ROOT="$HOME/Recon/${DOMAIN}/${RUN}"
mkdir -p "$ROOT"; cd "$ROOT"
PFX=""
[[ "$PROXY" == "tor" ]] && PFX="proxychains4 -q"

echo "[*] Subdomain discovery…"
$PFX subfinder -silent -all -d "$DOMAIN" -o subs_subfinder.txt || true
$PFX amass enum -passive -d "$DOMAIN" -o subs_amass.txt 2>/dev/null || true
cat subs_* 2>/dev/null | sort -u > subs.txt
echo "[+] Total subs: $(wc -l < subs.txt)"

echo "[*] Probing with httpx…"
$PFX httpx -l subs.txt -status-code -title -ip -tech-detect -follow-redirects -no-color -o httpx.txt || true
cut -d' ' -f1 httpx.txt | sed 's|\].*||;s|^\[||' | sort -u > hosts_httpx.txt || true
echo "[+] Alive: $(wc -l < hosts_httpx.txt)"

echo "[*] Nuclei (low/medium; safe baseline)…"
$PFX nuclei -l hosts_httpx.txt -severity low,medium -rate-limit 50 -duc -silent -no-color -stats -o nuclei.txt || true

{
  echo "=== Quick Recon Report ==="
  echo "Target:   $DOMAIN"
  echo "Run:      $RUN"
  echo "Subs:     $(wc -l < subs.txt)"
  echo "Alive:    $(wc -l < hosts_httpx.txt)"
  echo "Findings: $(wc -l < nuclei.txt)"
  echo
  echo "--- Sample titles ---"
  awk '{print $3" "$4" "$5" "$6" "$7" "$8" "$9}' httpx.txt | sort | uniq -c | sort -nr | head -20
} > report.txt

echo "[+] Done: $ROOT"
EOF
chmod +x /usr/local/bin/quick-recon

# ---------- helper: ti-health ----------
cat >/usr/local/bin/ti-health <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ok(){ printf "[OK] %s\n" "$*"; }
bad(){ printf "[!!] %s\n" "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "== Binary presence =="
for b in subfinder amass httpx nuclei proxychains4 torsocks spiderfoot theHarvester recon-ng tor nmap chromium; do
  have "$b" && ok "$b" || bad "missing: $b"
done

echo "== Tor service =="
systemctl is-active --quiet tor && ok "tor active" || bad "tor inactive"

echo "== Outbound IP (torsocks) =="
if have torsocks; then
  IP=$(torsocks curl -m 10 -s https://api.ipify.org || true)
  [[ -n "${IP:-}" ]] && ok "torsocks IP: $IP" || bad "torsocks curl failed"
fi

echo "== Outbound IP (proxychains4) =="
if have proxychains4; then
  IP=$((proxychains4 -q curl -m 10 -s https://api.ipify.org) 2>/dev/null || true)
  [[ -n "${IP:-}" ]] && ok "proxychains IP: $IP" || bad "proxychains curl failed"
fi

echo "== Versions =="
for b in subfinder httpx naabu nuclei katana amass; do
  have "$b" && "$b" -version 2>/dev/null | head -1 || true
done
EOF
chmod +x /usr/local/bin/ti-health

# ---------- helper: ti-update ----------
cat >/usr/local/bin/ti-update <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[*] apt update/upgrade…"
apt-get update -y && apt-get -y -o Dpkg::Options::="--force-confold" dist-upgrade || true
echo "[*] pip tools update…"
python3 -m pip install -U pip holehe knockpy email2phonenumber maigret feedparser tldextract volatility3 || true
echo "[*] ProjectDiscovery self-update…"
for t in subfinder httpx naabu nuclei katana; do
  command -v "$t" >/dev/null 2>&1 && "$t" -update || true
done
echo "[*] Nuclei templates…"
command -v nuclei >/dev/null 2>&1 && nuclei -update -ut || true
echo "[+] Update complete."
EOF
chmod +x /usr/local/bin/ti-update

# ---------- helper: iocgrab ----------
cat >/usr/local/bin/iocgrab <<'EOF'
#!/usr/bin/env python3
import re, sys, csv, os, time
text = sys.stdin.read() if len(sys.argv)==1 else open(sys.argv[1], 'r', errors='ignore').read()
regex = {
  "url": r"https?://[^\s\"'>)]+",
  "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b",
  "email": r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
  "md5": r"\b[a-fA-F0-9]{32}\b",
  "sha1": r"\b[a-fA-F0-9]{40}\b",
  "sha256": r"\b[a-fA-F0-9]{64}\b",
  "domain": r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b"
}
found=set()
for k,pat in regex.items():
  for m in re.findall(pat, text):
    found.add((k,m))
stamp=time.strftime("%Y%m%d-%H%M%S")
out=os.path.expanduser(f"~/OSINT/iocs-{stamp}.csv")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out,"w",newline="") as f:
  w=csv.writer(f); w.writerow(["type","value"])
  for row in sorted(found): w.writerow(row)
print(out)
EOF
chmod +x /usr/local/bin/iocgrab
chown "$REAL_USER":"$REAL_USER" /usr/local/bin/iocgrab

# ---------- helper: webshot ----------
cat >/usr/local/bin/webshot <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -lt 1 ]] && { echo "Usage: $0 <url> [outfile.png]"; exit 1; }
URL="$1"; OUT="${2:-screenshot-$(date +%Y%m%d-%H%M%S).png}"
BIN="$(command -v chromium || command -v chromium-browser)"
[[ -z "$BIN" ]] && { echo "chromium not found"; exit 2; }
"$BIN" --headless --disable-gpu --no-sandbox --virtual-time-budget=10000 --window-size=1366,768 --screenshot="$OUT" "$URL"
echo "$OUT"
EOF
chmod +x /usr/local/bin/webshot

# ---------- helper: new-case ----------
cat >/usr/local/bin/new-case <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${1:-}" ]] && { echo "Usage: $0 <case-slug>"; exit 1; }
STAMP="$(date +%Y%m%d)"
ROOT="$HOME/Cases/CASE-${STAMP}-${1}"
mkdir -p "$ROOT"/{captures,iocs,notes,screenshots,exports,logs}
cat >"$ROOT/README.txt" <<TXT
Case:    ${1}
Opened:  ${STAMP}
Owner:   $(whoami)
Scope:   (describe authorized scope here)
Chain-of-custody:
 - Start time:
 - Evidence list:
 - Transfers:
TXT
echo "$ROOT"
EOF
chmod +x /usr/local/bin/new-case
chown "$REAL_USER":"$REAL_USER" -R "$USER_HOME/Cases"

# ---------- helper: ti-feeds (RSS -> SQLite) ----------
mkdir -p /opt/ti-feeds
cat >/opt/ti-feeds/ti-feeds.py <<'EOF'
#!/usr/bin/env python3
import os, sqlite3, time, feedparser
DB=os.path.expanduser("~/OSINT/feeds.db")
FEEDS=[
  ("CISA Alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
  ("NVD CVE Recent", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"),
  ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
  ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
  ("ProjectDiscovery Blog", "https://blog.projectdiscovery.io/rss/"),
  ("Tor Project Blog", "https://blog.torproject.org/feed.xml"),
]
os.makedirs(os.path.dirname(DB), exist_ok=True)
con=sqlite3.connect(DB); cur=con.cursor()
cur.execute("""CREATE TABLE IF NOT EXISTS items(
  feed TEXT, guid TEXT PRIMARY KEY, title TEXT, link TEXT, published TEXT, fetched_at INTEGER)""")
con.commit()
new=0
for name,url in FEEDS:
  d=feedparser.parse(url)
  for e in d.entries:
    guid=getattr(e,"id",None) or getattr(e,"guid",None) or getattr(e,"link","")
    title=getattr(e,"title",""); link=getattr(e,"link","")
    pub=getattr(e,"published","") or getattr(e,"updated","")
    try:
      cur.execute("INSERT INTO items(feed,guid,title,link,published,fetched_at) VALUES (?,?,?,?,?,?)",
                  (name,guid,title,link,pub,int(time.time())))
      con.commit(); new+=1
      print(f"[NEW][{name}] {title}\n  {link}")
    except sqlite3.IntegrityError:
      pass
con.close()
print(f"[+] New items: {new}")
EOF
chmod +x /opt/ti-feeds/ti-feeds.py
ln -sf /opt/ti-feeds/ti-feeds.py /usr/local/bin/ti-feeds

# ---------- convenience alias ----------
grep -qxF "alias qr='quick-recon -d'" "$BRC" || echo "alias qr='quick-recon -d'" >> "$BRC"

# ---------- summary ----------
echo
echo "======== Summary ========"
echo "User:      $REAL_USER"
echo "Home:      $USER_HOME"
echo "Preset:    $PRESET"
echo "Offsec:    $([[ $WITH_OFFSEC -eq 1 ]] && echo ENABLED || echo disabled)"
echo "UFW:       $([[ $ENABLE_UFW -eq 1 ]] && echo enabled || echo skipped)"
echo "Proxy:     $QC_PROXY (for quick-recon: use --proxy tor|none)"
echo "Helpers:   quick-recon, ti-health, ti-update, iocgrab, webshot, new-case, ti-feeds"
echo "Tip:       Open a NEW terminal to load aliases"
echo "========================="
ok "Setup complete."
