#!/usr/bin/env bash
# Kalitelligence v3.0 - Feature Enhancement Patch
# This script adds new features to the existing kalitelligence.sh installation
# Run AFTER the main installation is complete

set -euo pipefail

echo "========================================="
echo "  Kalitelligence v3.0 Feature Installer"
echo "========================================="
echo

# Detect user home
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  REAL_USER="${SUDO_USER}"
else
  REAL_USER="$(logname 2>/dev/null || echo root)"
fi
USER_HOME="$(eval echo ~${REAL_USER})"

LOG_DIR="/var/log/ti-suite"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/feature-install-$(date +%Y%m%d-%H%M%S).log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
ok() { echo -e "\033[0;32m[✓]\033[0m $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "\033[0;33m[!]\033[0m $*" | tee -a "$LOG_FILE" >&2; }

# ========== FEATURE 1: REST API Server ==========
install_rest_api() {
    log "Installing REST API server..."
    
    # Install FastAPI and dependencies
    if [[ -d "$USER_HOME/.ti-venv" ]]; then
        source "$USER_HOME/.ti-venv/bin/activate"
        pip install -q fastapi uvicorn python-multipart pydantic python-jose[cryptography] passlib[bcrypt] 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # Create API directory
    mkdir -p /opt/ti-api
    
    # Create the REST API application
    cat > /opt/ti-api/main.py <<'APICODE'
#!/usr/bin/env python3
"""
Kalitelligence REST API Server
Provides programmatic access to TI suite functionality
"""
import os
import sys
import json
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Configuration
APP_VERSION = "3.0.0"
USER_HOME = os.path.expanduser("~")
TI_SUITE_DIR = Path(USER_HOME) / ".ti-suite"
CASES_DIR = Path(USER_HOME) / "Cases"
RECON_DIR = Path(USER_HOME) / "Recon"
OSINT_DIR = Path(USER_HOME) / "OSINT"
DB_PATH = OSINT_DIR / "ti-feeds.db"

app = FastAPI(
    title="Kalitelligence API",
    description="Threat Intelligence Suite REST API",
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class IOCRequest(BaseModel):
    text: str
    ioc_types: Optional[List[str]] = None

class ReconRequest(BaseModel):
    domain: str
    deep: bool = False
    screenshot: bool = False
    parallel: int = 4

class CaseCreate(BaseModel):
    name: str
    case_type: str = "osint"
    client: Optional[str] = None
    ticket: Optional[str] = None

class IOCEnrichmentRequest(BaseModel):
    ioc: str
    ioc_type: str

class EnrichmentResult(BaseModel):
    ioc: str
    type: str
    vt_report: Optional[Dict] = None
    shodan_report: Optional[Dict] = None
    risk_score: int = 0

# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": APP_VERSION,
        "timestamp": datetime.now().isoformat()
    }

# System info
@app.get("/system")
async def system_info():
    import platform
    import psutil
    
    return {
        "platform": platform.system(),
        "python_version": sys.version,
        "cpu_count": psutil.cpu_count(),
        "memory_total": psutil.virtual_memory().total,
        "disk_usage": psutil.disk_usage(str(USER_HOME))._asdict()
    }

# IOC Extraction endpoint
@app.post("/api/v1/ioc/extract")
async def extract_iocs(request: IOCRequest):
    """Extract IOCs from text"""
    import re
    from collections import defaultdict
    
    patterns = {
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b",
        "url": r"https?://[^\s\"'<>)]+",
        "email": r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "domain": r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    }
    
    found = defaultdict(list)
    for ioc_type, pattern in patterns.items():
        if request.ioc_types is None or ioc_type in request.ioc_types:
            matches = re.findall(pattern, request.text, re.IGNORECASE)
            found[ioc_type] = list(set(matches))
    
    return {
        "total": sum(len(v) for v in found.values()),
        "iocs": dict(found)
    }

# Reconnaissance endpoint
@app.post("/api/v1/recon/start")
async def start_recon(request: ReconRequest, background_tasks: BackgroundTasks):
    """Start reconnaissance scan"""
    job_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = RECON_DIR / request.domain / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    async def run_recon():
        try:
            cmd = [
                "/usr/local/bin/quick-recon",
                "-d", request.domain,
                "--parallel", str(request.parallel)
            ]
            if request.deep:
                cmd.append("--deep")
            if request.screenshot:
                cmd.append("--screenshot")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Save result
            with open(output_dir / "api_result.json", "w") as f:
                json.dump({
                    "job_id": job_id,
                    "status": "completed",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }, f, indent=2)
        except Exception as e:
            with open(output_dir / "api_result.json", "w") as f:
                json.dump({
                    "job_id": job_id,
                    "status": "failed",
                    "error": str(e)
                }, f, indent=2)
    
    background_tasks.add_task(run_recon)
    
    return {
        "job_id": job_id,
        "status": "started",
        "output_dir": str(output_dir)
    }

# Cases management
@app.get("/api/v1/cases")
async def list_cases(status: Optional[str] = None):
    """List all cases"""
    cases = []
    if CASES_DIR.exists():
        for case_dir in CASES_DIR.glob("CASE-*"):
            info_file = case_dir / "case-info.json"
            if info_file.exists():
                with open(info_file) as f:
                    case_info = json.load(f)
                    if status is None or case_info.get("status") == status:
                        cases.append(case_info)
    return {"cases": cases}

@app.post("/api/v1/cases")
async def create_case(case: CaseCreate):
    """Create new case"""
    stamp = datetime.now().strftime("%Y%m%d")
    case_id = f"CASE-{stamp}-{case.name.lower().replace(' ', '-')}"
    case_dir = CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    
    case_info = {
        "case_id": case_id,
        "case_name": case.name,
        "type": case.case_type,
        "client": case.client,
        "ticket": case.ticket,
        "opened": datetime.now().isoformat(),
        "status": "open"
    }
    
    with open(case_dir / "case-info.json", "w") as f:
        json.dump(case_info, f, indent=2)
    
    return case_info

# Threat Intel feeds
@app.get("/api/v1/feeds")
async def get_feeds(limit: int = 20, feed: Optional[str] = None):
    """Get threat intelligence feeds"""
    if not DB_PATH.exists():
        raise HTTPException(status_code=404, detail="No feeds database found")
    
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if feed:
        cur.execute(
            "SELECT * FROM feeds WHERE feed = ? ORDER BY fetched_at DESC LIMIT ?",
            (feed, limit)
        )
    else:
        cur.execute(
            "SELECT * FROM feeds ORDER BY fetched_at DESC LIMIT ?",
            (limit,)
        )
    
    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    return {"feeds": results, "count": len(results)}

@app.get("/api/v1/feeds/search")
async def search_feeds(query: str = Query(..., min_length=3)):
    """Search threat intelligence feeds"""
    if not DB_PATH.exists():
        raise HTTPException(status_code=404, detail="No feeds database found")
    
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute(
        """SELECT feed, title, link, published, summary
           FROM feeds
           WHERE title LIKE ? OR summary LIKE ?
           ORDER BY fetched_at DESC
           LIMIT 50""",
        (f"%{query}%", f"%{query}%")
    )
    
    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    return {"results": results, "count": len(results)}

# Statistics
@app.get("/api/v1/stats")
async def get_statistics():
    """Get suite statistics"""
    stats = {
        "cases": 0,
        "recon_jobs": 0,
        "ioc_count": 0,
        "feed_items": 0
    }
    
    if CASES_DIR.exists():
        stats["cases"] = len(list(CASES_DIR.glob("CASE-*")))
    
    if RECON_DIR.exists():
        for domain_dir in RECON_DIR.iterdir():
            if domain_dir.is_dir():
                stats["recon_jobs"] += len(list(domain_dir.iterdir()))
    
    if DB_PATH.exists():
        conn = sqlite3.connect(str(DB_PATH))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM feeds")
        stats["feed_items"] = cur.fetchone()[0]
        conn.close()
    
    return stats

# Main entry point
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
APICODE

    # Create systemd service
    cat > /etc/systemd/system/ti-api.service <<'SYSTEMD'
[Unit]
Description=Kalitelligence REST API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ti-api
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/bin/python3 /opt/ti-api/main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    systemctl enable ti-api
    systemctl start ti-api
    
    ok "REST API server installed and started on port 8080"
    ok "API documentation available at: http://localhost:8080/docs"
}

# ========== FEATURE 2: TUI Dashboard ==========
install_tui_dashboard() {
    log "Installing Terminal UI dashboard..."
    
    if [[ -d "$USER_HOME/.ti-venv" ]]; then
        source "$USER_HOME/.ti-venv/bin/activate"
        pip install -q rich textual 2>&1 | tee -a "$LOG_FILE"
    fi
    
    cat > /usr/local/bin/ti-tui <<'TUICODE'
#!/usr/bin/env python3
"""
Kalitelligence Terminal UI Dashboard
Interactive terminal-based interface for TI suite
"""
import os
import subprocess
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
import time

console = Console()

USER_HOME = Path(os.path.expanduser("~"))
CASES_DIR = USER_HOME / "Cases"
RECON_DIR = USER_HOME / "Recon"
OSINT_DIR = USER_HOME / "OSINT"

def get_system_stats():
    """Get system statistics"""
    import shutil
    
    total, used, free = shutil.disk_usage(str(USER_HOME))
    
    try:
        result = subprocess.run(['uptime', '-p'], capture_output=True, text=True)
        uptime = result.stdout.strip()
    except:
        uptime = "unknown"
    
    return {
        "disk_used": used // (1024**3),
        "disk_free": free // (1024**3),
        "disk_percent": round(used / total * 100, 1),
        "uptime": uptime
    }

def get_active_cases():
    """Get active cases"""
    cases = []
    if CASES_DIR.exists():
        for case_dir in CASES_DIR.glob("CASE-*"):
            info_file = case_dir / "case-info.json"
            if info_file.exists():
                import json
                with open(info_file) as f:
                    info = json.load(f)
                    if info.get("status") == "open":
                        cases.append(info)
    return cases[:5]

def get_recent_recon():
    """Get recent recon jobs"""
    recon_jobs = []
    if RECON_DIR.exists():
        for domain_dir in sorted(RECON_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
            if domain_dir.is_dir():
                latest = max(domain_dir.iterdir(), key=lambda x: x.stat().st_mtime, default=None)
                if latest:
                    recon_jobs.append({
                        "domain": domain_dir.name,
                        "run": latest.name,
                        "time": datetime.fromtimestamp(latest.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    })
    return recon_jobs

def create_layout():
    """Create dashboard layout"""
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    layout["left"].split(
        Layout(name="cases"),
        Layout(name="recon")
    )
    return layout

def make_header():
    """Make header panel"""
    grid = Table.grid(expand=True)
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    
    grid.add_row(
        Text("🎯 Kalitelligence Dashboard", style="bold cyan"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    return Panel(grid, style="bold white on blue")

def make_footer():
    """Make footer panel"""
    return Panel(
        "Commands: q=Quit | r=Refresh | c=New Case | s=Stats",
        style="white on blue"
    )

def make_cases_panel():
    """Make cases panel"""
    cases = get_active_cases()
    
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Case ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Opened", style="green")
    
    for case in cases:
        table.add_row(
            case.get("case_id", "Unknown")[:20],
            case.get("type", "unknown"),
            case.get("opened", "")[:10] if case.get("opened") else ""
        )
    
    if not cases:
        table.add_row("No active cases", "", "")
    
    return Panel(table, title="📁 Active Cases", border_style="cyan")

def make_recon_panel():
    """Make recon panel"""
    jobs = get_recent_recon()
    
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Domain", style="yellow")
    table.add_column("Run", style="blue")
    table.add_column("Time", style="green")
    
    for job in jobs:
        table.add_row(
            job["domain"][:15],
            job["run"][-12:] if len(job["run"]) > 12 else job["run"],
            job["time"]
        )
    
    if not jobs:
        table.add_row("No recent jobs", "", "")
    
    return Panel(table, title="🔍 Recent Recon", border_style="yellow")

def make_stats_panel():
    """Make stats panel"""
    stats = get_system_stats()
    
    grid = Table.grid(expand=True)
    grid.add_column(style="bold cyan")
    grid.add_column(style="white")
    
    grid.add_row("Disk Used:", f"{stats['disk_used']} GB ({stats['disk_percent']}%)")
    grid.add_row("Disk Free:", f"{stats['disk_free']} GB")
    grid.add_row("Uptime:", stats['uptime'])
    
    # Count totals
    case_count = len(list(CASES_DIR.glob("CASE-*"))) if CASES_DIR.exists() else 0
    recon_count = sum(1 for d in RECON_DIR.iterdir() if d.is_dir()) if RECON_DIR.exists() else 0
    
    grid.add_row("", "")
    grid.add_row("Total Cases:", str(case_count))
    grid.add_row("Total Recon Jobs:", str(recon_count))
    
    return Panel(grid, title="📊 System Stats", border_style="green")

def main_loop():
    """Main dashboard loop"""
    layout = create_layout()
    
    layout["header"].update(make_header())
    layout["footer"].update(make_footer())
    layout["left"]["cases"].update(make_cases_panel())
    layout["left"]["recon"].update(make_recon_panel())
    layout["right"].update(make_stats_panel())
    
    with Live(layout, refresh_per_second=1, screen=True) as live:
        while True:
            time.sleep(1)
            layout["header"].update(make_header())
            layout["left"]["cases"].update(make_cases_panel())
            layout["left"]["recon"].update(make_recon_panel())
            layout["right"].update(make_stats_panel())

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Dashboard closed[/bold yellow]")
TUICODE

    chmod +x /usr/local/bin/ti-tui
    ok "TUI dashboard installed (run: ti-tui)"
}

# ========== FEATURE 3: IOC Enrichment ==========
install_ioc_enrichment() {
    log "Installing IOC enrichment tool..."
    
    cat > /usr/local/bin/ti-enrich <<'ENRICHCODE'
#!/usr/bin/env python3
"""
IOC Enrichment Tool
Enriches IOCs with threat intelligence from multiple sources
"""
import argparse
import json
import os
import sys
import requests
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path.home() / ".ti-suite" / "config.json"

def load_config():
    """Load API keys from config"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def enrich_vt(ioc, ioc_type, api_key):
    """Enrich with VirusTotal"""
    if not api_key:
        return None
    
    try:
        headers = {"x-apikey": api_key}
        
        if ioc_type in ["md5", "sha1", "sha256"]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type in ["ipv4", "ipv6", "domain"]:
            url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if ioc_type.startswith('ip') else 'domains'}/{ioc}"
        else:
            return None
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "detected": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0)
            }
    except Exception as e:
        print(f"VT error: {e}", file=sys.stderr)
    
    return None

def enrich_shodan(ioc, api_key):
    """Enrich with Shodan"""
    if not api_key or ioc_type != "ipv4":
        return None
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ioc}"
        params = {"key": api_key}
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "org": data.get("org"),
                "country": data.get("country_name"),
                "open_ports": len(data.get("ports", [])),
                "vulns": len(data.get("vulns", []))
            }
    except Exception as e:
        print(f"Shodan error: {e}", file=sys.stderr)
    
    return None

def calculate_risk(vt_data, shodan_data):
    """Calculate risk score"""
    score = 0
    
    if vt_data:
        detected = vt_data.get("detected", {})
        malicious = detected.get("malicious", 0)
        suspicious = detected.get("suspicious", 0)
        
        if malicious > 5:
            score += 50
        elif malicious > 0:
            score += 25
        
        if suspicious > 5:
            score += 25
        
        reputation = vt_data.get("reputation", 0)
        if reputation < -50:
            score += 30
        elif reputation < 0:
            score += 15
    
    if shodan_data:
        vulns = shodan_data.get("vulns", 0)
        if vulns > 5:
            score += 30
        elif vulns > 0:
            score += 15
        
        score += min(shodan_data.get("open_ports", 0), 20)
    
    return min(score, 100)

def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs with threat intelligence")
    parser.add_argument("ioc", help="Indicator of Compromise")
    parser.add_argument("-t", "--type", required=True, 
                       choices=["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"],
                       help="IOC type")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--shodan-key", help="Shodan API key")
    
    args = parser.parse_args()
    
    # Load config for API keys
    config = load_config()
    vt_key = args.vt_key or config.get("vt_api_key")
    shodan_key = args.shodan_key or config.get("shodan_api_key")
    
    # Enrich
    vt_result = enrich_vt(args.ioc, args.type, vt_key)
    shodan_result = enrich_shodan(args.ioc, shodan_key) if args.type == "ipv4" else None
    
    risk_score = calculate_risk(vt_result, shodan_result)
    
    # Output
    result = {
        "ioc": args.ioc,
        "type": args.type,
        "timestamp": datetime.now().isoformat(),
        "virustotal": vt_result,
        "shodan": shodan_result,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"
    }
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"IOC: {result['ioc']} ({result['type']})")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Risk Score: {result['risk_score']}/100 ({result['risk_level'].upper()})")
        
        if vt_result:
            print(f"\nVirusTotal:")
            print(f"  Detected: {vt_result.get('detected', {})}")
            print(f"  Reputation: {vt_result.get('reputation', 'N/A')}")
        
        if shodan_result:
            print(f"\nShodan:")
            print(f"  Organization: {shodan_result.get('org', 'N/A')}")
            print(f"  Country: {shodan_result.get('country', 'N/A')}")
            print(f"  Open Ports: {shodan_result.get('open_ports', 0)}")
            print(f"  Vulnerabilities: {shodan_result.get('vulns', 0)}")
        
        print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
ENRICHCODE

    chmod +x /usr/local/bin/ti-enrich
    ok "IOC enrichment tool installed (run: ti-enrich)"
}

# ========== FEATURE 4: Export Tools ==========
install_export_tools() {
    log "Installing export tools..."
    
    cat > /usr/local/bin/ti-export <<'EXPORTCODE'
#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<USAGE
ti-export - Export TI suite data in various formats

Usage: $0 <command> [OPTIONS]

Commands:
  cases       Export case data
  iocs        Export extracted IOCs
  recon       Export reconnaissance results
  feeds       Export threat intelligence feeds
  stix        Export as STIX 2.1 format

Options:
  -o, --output FILE     Output file
  -f, --format FORMAT   Format: json|csv|xml|stix (default: json)
  -c, --case CASE_ID    Specific case ID
  -h, --help           Show this help

Examples:
  $0 cases -o all-cases.json
  $0 iocs -f csv -o iocs.csv
  $0 stix -o threat-intel.stix.json
USAGE
    exit 1
}

[[ $# -lt 1 ]] && usage

COMMAND="$1"
shift

OUTPUT=""
FORMAT="json"
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT="$2"; shift 2;;
        -f|--format) FORMAT="$2"; shift 2;;
        -c|--case) CASE_ID="$2"; shift 2;;
        -h|--help) usage;;
        *) shift;;
    esac
done

USER_HOME="$HOME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

export_cases() {
    local output="${OUTPUT:-$HOME/Exports/cases-${TIMESTAMP}.json}"
    mkdir -p "$(dirname "$output")"
    
    echo "[" > "$output"
    first=true
    
    if [[ -n "$CASE_ID" ]]; then
        case_dirs=("$HOME/Cases/$CASE_ID")
    else
        case_dirs=("$HOME/Cases"/CASE-*)
    fi
    
    for case_dir in "${case_dirs[@]}"; do
        [[ -d "$case_dir" ]] || continue
        info_file="$case_dir/case-info.json"
        [[ -f "$info_file" ]] || continue
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$output"
        fi
        
        cat "$info_file" >> "$output"
    done
    
    echo "]" >> "$output"
    echo "[+] Exported cases to: $output"
}

export_iocs() {
    local output="${OUTPUT:-$HOME/Exports/iocs-${TIMESTAMP}.${FORMAT}}"
    mkdir -p "$(dirname "$output")"
    
    find "$HOME/OSINT" -name "iocs-*.csv" -exec cat {} \; > /tmp/all-iocs.csv 2>/dev/null || true
    
    if [[ "$FORMAT" == "csv" ]]; then
        mv /tmp/all-iocs.csv "$output"
    else
        echo "[" > "$output"
        tail -n +2 /tmp/all-iocs.csv | while IFS=, read -r type value count; do
            echo "{\"type\":\"$type\",\"value\":\"$value\",\"count\":$count}," >> "$output"
        done
        sed -i '$ s/,$//' "$output"
        echo "]" >> "$output"
    fi
    
    echo "[+] Exported IOCs to: $output"
}

export_stix() {
    local output="${OUTPUT:-$HOME/Exports/threat-intel-${TIMESTAMP}.stix.json}"
    mkdir -p "$(dirname "$output")"
    
    cat > "$output" <<STIX
{
  "type": "bundle",
  "id": "bundle--$(uuidgen 2>/dev/null || echo $(date +%s))",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--kalitelligence",
      "created": "$(date -Iseconds)",
      "modified": "$(date -Iseconds)",
      "name": "Kalitelligence TI Suite",
      "identity_class": "system"
    }
  ]
}
STIX
    
    echo "[+] Exported STIX bundle to: $output"
}

case "$COMMAND" in
    cases) export_cases;;
    iocs) export_iocs;;
    stix) export_stix;;
    *) echo "Unknown command: $COMMAND"; usage;;
esac
EXPORTCODE

    chmod +x /usr/local/bin/ti-export
    ok "Export tools installed (run: ti-export)"
}

# ========== FEATURE 5: Playbook Automation ==========
install_playbooks() {
    log "Installing automation playbooks..."
    
    # Install Ansible if not present
    if ! command -v ansible-playbook &>/dev/null; then
        apt_update_once() {
            if [[ ! -f /var/cache/ti-suite/apt_updated ]]; then
                apt-get update -y >/dev/null 2>&1
                touch /var/cache/ti-suite/apt_updated
            fi
        }
        apt_update_once
        apt-get install -y ansible >/dev/null 2>&1 | tee -a "$LOG_FILE"
    fi
    
    mkdir -p /opt/ti-playbooks
    
    # Create reconnaissance playbook
    cat > /opt/ti-playbooks/recon.yml <<'PLAYBOOK'
---
- name: Automated Reconnaissance Playbook
  hosts: localhost
  connection: local
  gather_facts: false
  
  vars:
    target_domain: "{{ domain | default('example.com') }}"
    recon_date: "{{ ansible_date_time.iso8601 }}"
    output_dir: "~/Recon/{{ target_domain }}/{{ ansible_date_time.date }}"
  
  tasks:
    - name: Create output directory
      file:
        path: "{{ output_dir }}"
        state: directory
        mode: '0755'
    
    - name: Run subdomain enumeration
      shell: |
        subfinder -silent -all -d {{ target_domain }} -o {{ output_dir }}/subs.txt
      args:
        executable: /bin/bash
      ignore_errors: yes
    
    - name: Run port scanning
      shell: |
        naabu -silent -list {{ output_dir }}/subs.txt -top-ports 1000 -o {{ output_dir }}/ports.txt
      args:
        executable: /bin/bash
      ignore_errors: yes
    
    - name: Run HTTP probing
      shell: |
        httpx -l {{ output_dir }}/subs.txt -status-code -title -ip -tech-detect -silent -no-color -o {{ output_dir }}/httpx.txt
      args:
        executable: /bin/bash
      ignore_errors: yes
    
    - name: Generate summary
      lineinfile:
        path: "{{ output_dir }}/summary.md"
        line: "# Reconnaissance Summary\n\n**Target:** {{ target_domain }}\n**Date:** {{ recon_date }}\n\nCompleted automated reconnaissance."
        create: yes
    
    - name: Display completion message
      debug:
        msg: "Reconnaissance complete for {{ target_domain }}. Results in {{ output_dir }}"
PLAYBOOK

    # Create IOC monitoring playbook
    cat > /opt/ti-playbooks/ioc-monitor.yml <<'PLAYBOOK'
---
- name: IOC Monitoring Playbook
  hosts: localhost
  connection: local
  gather_facts: false
  
  vars:
    ioc_list: "{{ iocs | default([]) }}"
    output_file: "~/OSINT/ioc-monitoring-{{ ansible_date_time.date }}.json"
  
  tasks:
    - name: Process each IOC
      shell: |
        ti-enrich {{ item }} -t {{ item_type | default('domain') }} -j
      loop: "{{ ioc_list }}"
      register: enrichment_results
      ignore_errors: yes
    
    - name: Save results
      copy:
        content: "{{ enrichment_results.results | map(attribute='stdout') | list | to_json(indent=2) }}"
        dest: "{{ output_file }}"
      when: enrichment_results.results | length > 0
PLAYBOOK

    # Create daily report playbook
    cat > /opt/ti-playbooks/daily-report.yml <<'PLAYBOOK'
---
- name: Daily TI Report Generation
  hosts: localhost
  connection: local
  gather_facts: false
  
  vars:
    report_date: "{{ ansible_date_time.date }}"
    output_dir: "~/Reports/daily"
  
  tasks:
    - name: Create reports directory
      file:
        path: "{{ output_dir }}"
        state: directory
    
    - name: Generate daily report
      shell: |
        ti-report ~/Recon -o {{ output_dir }}/daily-{{ report_date }}.html -f html --title "Daily Report {{ report_date }}"
      args:
        executable: /bin/bash
      ignore_errors: yes
    
    - name: Notify completion
      debug:
        msg: "Daily report generated: {{ output_dir }}/daily-{{ report_date }}.html"
PLAYBOOK

    # Create runner script
    cat > /usr/local/bin/ti-playbook <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<USAGE
ti-playbook - Run automation playbooks

Usage: $0 <playbook> [OPTIONS]

Playbooks:
  recon         Run reconnaissance automation
  ioc-monitor   Monitor and enrich IOCs
  daily-report  Generate daily reports
  custom        Run custom playbook

Options:
  -v, --vars VAR=VAL   Set playbook variables
  -f, --file PATH      Custom playbook file
  -h, --help          Show this help

Examples:
  $0 recon --vars domain=example.com
  $0 ioc-monitor --vars 'iocs=["evil.com", "bad.org"]'
  $0 custom -f /path/to/playbook.yml
USAGE
    exit 1
}

[[ $# -lt 1 ]] && usage

PLAYBOOK_NAME="$1"
shift

EXTRA_VARS=""
CUSTOM_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--vars) EXTRA_VARS="$EXTRA_VARS -e $2"; shift 2;;
        -f|--file) CUSTOM_FILE="$2"; shift 2;;
        -h|--help) usage;;
        *) shift;;
    esac
done

case "$PLAYBOOK_NAME" in
    recon)
        ansible-playbook /opt/ti-playbooks/recon.yml $EXTRA_VARS
        ;;
    ioc-monitor)
        ansible-playbook /opt/ti-playbooks/ioc-monitor.yml $EXTRA_VARS
        ;;
    daily-report)
        ansible-playbook /opt/ti-playbooks/daily-report.yml $EXTRA_VARS
        ;;
    custom)
        [[ -n "$CUSTOM_FILE" ]] || { echo "Custom file required"; exit 1; }
        ansible-playbook "$CUSTOM_FILE" $EXTRA_VARS
        ;;
    *)
        echo "Unknown playbook: $PLAYBOOK_NAME"
        usage
        ;;
esac
RUNNER

    chmod +x /usr/local/bin/ti-playbook
    ok "Playbook automation installed (run: ti-playbook)"
}

# ========== MAIN INSTALLATION ==========
echo "Select features to install:"
echo "  1) REST API Server"
echo "  2) TUI Dashboard"
echo "  3) IOC Enrichment"
echo "  4) Export Tools"
echo "  5) Playbook Automation"
echo "  6) All Features"
echo "  7) Exit"
echo

read -p "Enter choice (1-7): " choice

case $choice in
    1) install_rest_api;;
    2) install_tui_dashboard;;
    3) install_ioc_enrichment;;
    4) install_export_tools;;
    5) install_playbooks;;
    6)
        install_rest_api
        install_tui_dashboard
        install_ioc_enrichment
        install_export_tools
        install_playbooks
        ;;
    7) exit 0;;
    *) echo "Invalid choice"; exit 1;;
esac

echo
echo "========================================="
echo "  Feature Installation Complete!"
echo "========================================="
echo
echo "New commands available:"
[[ -f /usr/local/bin/ti-api ]] && echo "  • ti-api (or systemctl start ti-api) - REST API server"
[[ -f /usr/local/bin/ti-tui ]] && echo "  • ti-tui - Terminal UI dashboard"
[[ -f /usr/local/bin/ti-enrich ]] && echo "  • ti-enrich - IOC enrichment"
[[ -f /usr/local/bin/ti-export ]] && echo "  • ti-export - Data export"
[[ -f /usr/local/bin/ti-playbook ]] && echo "  • ti-playbook - Automation playbooks"
echo
echo "Documentation: /opt/ti-suite/README.md"
echo "Log file: $LOG_FILE"
echo "========================================="
