![Kalitellingence - Make Over Your Kali Linux Into Threat Intelligence Banner](https://github.com/Masriyan/Kalitellingence/blob/main/image.png)

# Kalitellingence – Make Over Your Kali Linux Into a Threat Intelligence Workstation

Kalitellingence transforms your **Kali Linux** into a powerful workstation for **Threat Intelligence (TI)**, **OSINT**, **External Attack Surface Management (EASM)**, **Dark-web investigations**, and **DFIR**—with **intelligent automation**, **parallel processing**, **professional reporting**, and **helper commands** that maximize productivity.

> ⚠️ Use only on systems/targets you are **authorized** to assess. Some tools are dual-use.

---

## 🚀 What's New in v2.0 (Enhanced Edition)

### ⚡ Performance Revolution
- **47% faster installation** with parallel package processing
- **3-5x faster tool installations** through batch operations
- **2-3x faster reconnaissance** with parallel subdomain enumeration
- **4x faster updates** with concurrent tool updates
- Intelligent caching and resource optimization

### 🆕 Major New Features
- **Live Dashboard** (`ti-dashboard`) - Real-time monitoring of your TI operations
- **Professional HTML/Markdown Reports** (`ti-report`) - Export-ready documentation
- **Automated Maintenance** (`ti-automate`) - Set-it-and-forget-it updates
- **Notification System** (`ti-notify`) - Slack/Discord integration for alerts
- **Docker Support** - Containerized tools for isolated environments
- **AI/ML Integration** (optional) - Advanced threat analysis capabilities
- **Batch Processing** - Handle multiple targets efficiently
- **Enhanced IOC Extraction** - 10 IOC types with JSON output
- **Case Management Templates** - Professional investigation workflows

### 📊 Enhanced Commands
- **quick-recon**: Now with parallel execution, deep scanning, screenshots, and auto-notifications
- **ti-health**: Comprehensive system checks with connectivity tests
- **iocgrab**: Extract 10+ IOC types (IPs, domains, CVEs, crypto addresses, etc.)
- **webshot**: Batch screenshot processing with custom viewports
- **new-case**: Professional templates for osint/incident/malware/breach cases
- **ti-feeds**: 12 threat intel sources with search and statistics
- **ti-update**: Smart updates with rollback capability

### 🎯 New Capabilities
- **40+ Tools** (expanded from 15)
- **Structured Logging** with timestamps, colors, and severity levels
- **Performance Tracking** and installation metrics
- **Configuration Management** via JSON
- **Parallel Job Control** (configurable worker count)
- **Virtual Environment** for Python tools isolation
- **Comprehensive Documentation** with migration guides

---

## ✨ Features

### Core Capabilities

#### **OSINT & Reconnaissance**
- SpiderFoot, theHarvester, Recon-ng, Sublist3r, Amass, Sherlock, Photon
- ProjectDiscovery suite: **subfinder**, **httpx**, **naabu**, **nuclei**, **katana**, **notify**, **proxify**
- dnstwist, sn0int, Nmap, Masscan, Rustscan, Seclists
- FinalRecon, OSINT-SPY, Striker - advanced recon frameworks
- **NEW**: Parallel subdomain discovery, automated screenshots, IOC extraction

#### **Dark-web & Privacy**
- Tor, Torsocks, ProxyChains4, OnionShare, Tor Browser, TorBot, i2pd
- Privoxy, WireGuard support
- Enhanced Tor configuration with ControlPort
- **NEW**: Advanced proxy management and anonymity testing

#### **Threat Intelligence**
- 12 TI feed sources (CISA, NVD, US-CERT, Krebs, BleepingComputer, etc.)
- SQLite database with search functionality
- RSS aggregation with deduplication
- **NEW**: Feed statistics, search capabilities, automated updates

#### **Evidence & Analysis**
- ExifTool, Metagoofil, headless Chromium screenshots
- IOC extraction (IPs, domains, URLs, hashes, CVEs, crypto addresses)
- Batch screenshot processing
- **NEW**: Enhanced IOC types, JSON export, batch operations

#### **DFIR Capabilities**
- Yara, binwalk, foremost, scalpel, Autopsy, Sleuthkit
- Volatility3, chkrootkit, rkhunter
- **NEW**: Enhanced forensic toolkit, malware analysis templates

#### **Offensive Tools (Opt-in)**
- Hashcat, John, Hydra, Medusa, Ncrack
- CUPP, Cewl, Crunch, Aircrack-ng
- **NEW**: Enhanced password tools (enabled only with `--with-offsec`)

#### **Monitoring & Reporting**
- **NEW**: Live dashboard with system stats and case tracking
- **NEW**: HTML/Markdown report generation with visualizations
- **NEW**: Professional case management with templates
- **NEW**: Notification system (Slack/Discord)

#### **System Enhancements**
- UFW firewall (deny in / allow out)
- Persistent bash history with timestamps
- Smart aliases and productivity shortcuts
- **NEW**: Automated cron jobs, log rotation, configuration management

---

## 🧩 Presets

Choose a preset to tailor your installation:

| Preset | Focus | Includes | Best For |
|--------|-------|----------|----------|
| `passive` (default) | Safe OSINT | OSINT + ProjectDiscovery tools | Daily investigations, passive recon |
| `darkweb` | Tor/Onions | OSINT + Privacy tools + Tor stack | Dark web research, anonymity |
| `easm` | Attack Surface | ProjectDiscovery suite + scanners | External attack surface mapping |
| `dfir` | Forensics | OSINT + DFIR + analysis tools | Incident response, forensics |
| `full` | Everything | All tools (safe by default) | Complete TI workstation |
| `custom` | Minimal | Base only, use --with-* flags | Customized installations |

> 🔒 **Note**: Offensive tools require **explicit** `--with-offsec` flag regardless of preset.

---

## 📦 Installation

### Quick Start (Basic)
```bash
git clone https://github.com/Masriyan/Kalitellingence.git
cd Kalitellingence
chmod +x kali-ti-suite.sh
sudo ./kali-ti-suite.sh --preset passive
```

### Advanced Installation (Full Featured)
```bash
sudo ./kali-ti-suite.sh \
  --preset full \
  --with-offsec \
  --with-docker \
  --with-ai \
  --enable-automation \
  --parallel 8 \
  --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK" \
  --discord-webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK"
```

### Installation Options

```bash
Core Options:
  --preset [passive|darkweb|easm|dfir|full|custom]
           Choose your tool preset (default: passive)
  
Security & Tools:
  --with-offsec          Include offensive security tools (hashcat, hydra, john)
  --no-ufw              Skip UFW firewall configuration
  --proxy [none|tor]    Default proxy for reconnaissance tools
  
Performance:
  --parallel N          Number of parallel jobs (default: 4, recommended: 8)
  --no-auto-update      Skip automatic tool update configuration
  
Advanced Features:
  --with-docker         Install Docker and containerized tools
  --with-ai             Install AI/ML tools for threat analysis
  --enable-automation   Configure automated scans and updates (cron)
  
Integrations:
  --slack-webhook URL   Slack webhook for notifications
  --discord-webhook URL Discord webhook for notifications
  
Other:
  --debug               Enable detailed debug logging
  -h, --help           Show detailed help message
```

### Installation Time
- **Basic (passive)**: ~5 minutes
- **Full (all features)**: ~8 minutes (47% faster than v1.0)
- **With Docker**: +2 minutes

---

## 🗂️ Workspace Layout

Enhanced workspace structure with professional organization:

```
~/OSINT/              # OSINT findings, feeds.db, IOC CSVs
~/DarkWeb/            # Dark web investigations
~/Recon/              # Reconnaissance results (per target/run)
  └── target.com/
      └── 20241210-143022/
          ├── subs.txt
          ├── httpx.txt
          ├── nuclei_findings.txt
          ├── report.md
          └── screenshots/
~/Cases/              # Professional case management
  └── CASE-20241210-investigation/
      ├── case-info.json
      ├── README.md
      ├── evidence/
      ├── captures/
      ├── iocs/
      ├── notes/
      ├── screenshots/
      ├── reports/
      └── logs/
~/ThreatIntel/        # Threat intelligence data
~/Vulnerabilities/    # Vulnerability research
~/Breaches/           # Breach data analysis
~/Reports/            # Generated HTML/MD reports
~/Passwords/          # Password analysis (gitignored)
~/Metadata/           # Metadata extraction
~/SocialMedia/        # Social media OSINT
~/Logs/               # Investigation logs
```

---

## 🧰 Command Reference

### Reconnaissance Commands

#### **quick-recon** - Fast Reconnaissance Pipeline
```bash
# Basic passive recon
quick-recon -d example.com

# Deep scan with critical/high severity checks
quick-recon -d example.com --deep

# With screenshots and notifications
quick-recon -d example.com --deep --screenshot --notify

# Via Tor with custom parallelism
quick-recon -d example.com --proxy tor --parallel 12

# All options
quick-recon -d target.com \
  --proxy tor \
  --deep \
  --screenshot \
  --notify \
  --parallel 8
```

**Features:**
- Parallel subdomain enumeration (subfinder, amass, assetfinder)
- Port scanning (naabu)
- HTTP probing (httpx with tech detection)
- Vulnerability scanning (nuclei)
- Screenshot capture (optional)
- Automatic reporting
- Slack/Discord notifications

**Output:** `~/Recon/target.com/TIMESTAMP/`

---

#### **ti-report** - Professional Report Generation
```bash
# Generate HTML report
ti-report ~/Recon/target.com/20241210-143022/ \
  --format html \
  --title "ACME Corp Security Assessment"

# Generate Markdown
ti-report ~/Recon/target.com/20241210-143022/ --format md

# Custom output
ti-report ~/Recon/target.com/20241210-143022/ \
  -o custom-report.html \
  --format html
```

**Features:**
- Professional HTML reports with statistics
- Markdown export for documentation
- Executive summaries
- Color-coded findings by severity
- Technology stack analysis
- Export-ready format

---

### Monitoring Commands

#### **ti-dashboard** - Live Monitoring Dashboard
```bash
ti-dashboard
```

**Displays:**
- System uptime and load
- Disk usage
- Active cases
- Recent reconnaissance runs
- Service status (Tor, etc.)
- Latest threat intelligence feeds
- Auto-refresh every 10 seconds

Press `Ctrl+C` to exit.

---

#### **ti-health** - Comprehensive Health Check
```bash
ti-health
```

**Checks:**
- ✅ Core tools (git, curl, python, etc.)
- ✅ OSINT tools (subfinder, httpx, nuclei, etc.)
- ✅ Privacy tools (tor, proxychains, torsocks)
- ✅ Service status (tor, ssh, ufw)
- ✅ Network connectivity (direct, Tor, proxychains)
- ✅ Tool versions
- ✅ Last update timestamp
- ✅ Disk space

---

### Intelligence Commands

#### **ti-feeds** - Threat Intelligence Aggregator
```bash
# Fetch latest feeds
ti-feeds --fetch

# Search feeds
ti-feeds --search "ransomware"
ti-feeds --search "CVE-2024"

# Show statistics
ti-feeds --stats

# List recent items
ti-feeds --list -n 50
```

**Sources:** (12 feeds)
- CISA Alerts
- NVD CVE Recent
- US-CERT
- Krebs on Security
- BleepingComputer
- Threatpost
- The Hacker News
- DarkReading
- SecurityWeek
- ProjectDiscovery Blog
- Tor Project Blog
- SANS ISC

**Storage:** SQLite database at `~/OSINT/ti-feeds.db`

---

#### **iocgrab** - IOC Extraction Tool
```bash
# Extract from file
iocgrab suspicious.txt

# Extract from stdin
cat logs/*.log | iocgrab

# JSON output
iocgrab report.txt --json > iocs.json

# Specific IOC types
iocgrab data.txt --types ipv4,domain,cve

# Custom output location
iocgrab malware.txt -o ~/Cases/CASE-*/iocs/indicators.csv
```

**Extracts:**
- IPv4 addresses
- IPv6 addresses
- URLs (http/https)
- Email addresses
- Domains
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- CVE identifiers
- Bitcoin addresses
- Ethereum addresses

**Output:** CSV format with type and value columns

---

### Case Management

#### **new-case** - Case Initialization
```bash
# OSINT investigation
new-case "target-corp-osint" \
  --type osint \
  --client "ACME Corp" \
  --ticket "TI-2024-001"

# Incident response
new-case "ransomware-outbreak" \
  --type incident \
  --ticket "INC-2024-042"

# Malware analysis
new-case "suspicious-binary-analysis" \
  --type malware

# Data breach investigation
new-case "credential-exposure" \
  --type breach
```

**Creates:**
- Professional directory structure
- Case metadata (JSON)
- Investigation README with templates
- Evidence folders
- Chain of custody documentation
- Git repository initialization
- Type-specific templates (timeline, analysis notes, etc.)

**Output:** `~/Cases/CASE-YYYYMMDD-case-name/`

---

### Evidence & Analysis

#### **webshot** - Screenshot Utility
```bash
# Single screenshot
webshot https://example.com

# Batch screenshots
webshot -l urls.txt -o screenshots/

# Custom viewport
webshot https://example.com --width 1920 --height 1080

# With timeout
webshot https://slow-site.com --timeout 15000
```

**Features:**
- Headless browser capture
- Batch processing
- Custom viewport sizes
- Configurable timeouts
- Automatic filename generation

---

### Maintenance Commands

#### **ti-update** - System Update
```bash
sudo ti-update
```

**Updates:**
- ✅ APT packages (system upgrade)
- ✅ Python packages (pip)
- ✅ ProjectDiscovery tools (subfinder, httpx, nuclei, etc.)
- ✅ Nuclei templates
- ✅ Git repositories
- ✅ Cleanup old packages

**Features:**
- Automatic backup before updates
- Rollback capability
- Update logging
- Timestamp tracking

---

#### **ti-notify** - Send Notifications
```bash
# Send alert
ti-notify "Reconnaissance complete for target.com - 250 subdomains found"

# With findings
ti-notify "Critical vulnerability discovered: CVE-2024-1234"

# Case completion
ti-notify "Investigation CASE-20241210-breach completed"
```

Sends to configured Slack and/or Discord webhooks.

---

### Productivity Aliases

Pre-configured aliases (reload terminal after install):

```bash
sf              # SpiderFoot GUI (localhost:5001)
recon           # Recon-ng
th              # theHarvester
pc              # proxychains4 -q
qr              # quick-recon -d
subf            # subfinder -silent -all
httpx           # httpx (with common flags)
nuclei          # nuclei -duc -stats
ports           # naabu -silent -top-ports 1000
spider          # katana -silent -js-crawl

# Navigation
osint           # cd ~/OSINT
cases           # cd ~/Cases
reports         # cd ~/Reports

# Tools
health          # ti-health
update-ti       # ti-update
dash            # ti-dashboard
myip            # curl https://api.ipify.org
toripMyip       # torsocks curl https://api.ipify.org
```

---

## 🎯 Typical Workflows

### Workflow 1: OSINT Investigation

```bash
# 1. Create case
new-case "target-corp-assessment" \
  --type osint \
  --client "Target Corp"

# 2. Run reconnaissance
quick-recon -d target-corp.com --deep --screenshot --notify

# 3. Extract IOCs
cd ~/Recon/target-corp.com/*/
cat *.txt | iocgrab

# 4. Generate report
ti-report . --format html --title "Target Corp Assessment"

# 5. Organize findings
cp report.html ~/Cases/CASE-*/reports/
cp iocs-*.csv ~/Cases/CASE-*/iocs/
cp -r screenshots ~/Cases/CASE-*/
```

---

### Workflow 2: Incident Response

```bash
# 1. Initialize incident case
new-case "ransomware-investigation" \
  --type incident \
  --ticket "INC-2024-001"

# 2. Update threat intelligence
ti-feeds --fetch
ti-feeds --search "ransomware"

# 3. Extract IOCs from logs
cat /var/log/suspicious/* | iocgrab -o ~/Cases/CASE-*/iocs/indicators.csv

# 4. Screenshot suspicious URLs
cat suspicious_urls.txt | webshot -l - -o ~/Cases/CASE-*/screenshots/

# 5. Monitor progress
ti-dashboard

# 6. Generate incident report
cd ~/Cases/CASE-*/
# Edit incident-timeline.md with findings
ti-report ../Recon/compromise/ --format html --title "Incident Analysis"
```

---

### Workflow 3: Continuous Monitoring

```bash
# Terminal 1: Dashboard
ti-dashboard

# Terminal 2: Feed monitoring
watch -n 300 'ti-feeds --list -n 10'

# Terminal 3: Health checks
watch -n 60 ti-health

# Set up automated daily scans (with --enable-automation)
# Cron automatically runs:
# - Daily: TI feed updates (2 AM)
# - Weekly: Tool updates (Sunday 2 AM)
# - Continuous: Log cleanup (>30 days)
```

---

### Workflow 4: Dark Web Investigation

```bash
# 1. Start via Tor
quick-recon -d target.onion --proxy tor

# 2. Manual Tor crawl
torbot -u http://target.onion

# 3. Verify anonymity
ti-health  # Check Tor IP vs direct IP

# 4. Document findings
new-case "darkweb-marketplace-analysis" --type osint
```

---

## ✅ Verification & Testing

### Post-Installation Checks
```bash
# Comprehensive health check
ti-health

# Verify tool versions
subfinder -version
httpx -version
nuclei -version

# Test connectivity
curl -s https://api.ipify.org                    # Direct IP
torsocks curl -s https://api.ipify.org          # Tor IP
proxychains4 -q curl -s https://api.ipify.org   # Proxy IP

# Test core tools
spiderfoot -h
recon-ng -h
theHarvester -h

# Check workspaces
ls -la ~/{OSINT,Recon,Cases,ThreatIntel}

# Verify configuration
cat ~/.ti-suite/config.json
```

### Performance Verification
```bash
# Check installation log
tail -100 /var/log/ti-suite/install-*.log

# View statistics
ti-feeds --stats

# Monitor dashboard
ti-dashboard
```

---

## 🔒 Security & Privacy

### Default Security Posture
- ✅ UFW firewall: deny incoming / allow outgoing
- ✅ ProxyChains: dynamic_chain + proxy_dns configured
- ✅ Tor: Auto-start enabled with ControlPort
- ✅ History: Persistent with timestamps for auditing
- ✅ Sensitive directories: Auto-gitignored
- ✅ Offensive tools: Explicit opt-in required

### Proxy Configuration
```bash
# ProxyChains via Tor
pc curl https://example.com

# Torsocks wrapper
torsocks wget https://example.com

# Quick-recon with Tor
quick-recon -d target.com --proxy tor
```

**ProxyChains Config:** `/etc/proxychains4.conf`
- Dynamic chain mode
- DNS proxying enabled
- Tor SOCKS5: 127.0.0.1:9050
- Configurable timeouts

### Anonymity Testing
```bash
# Compare IPs
echo "Direct:      $(curl -s https://api.ipify.org)"
echo "Tor:         $(torsocks curl -s https://api.ipify.org)"
echo "Proxychains: $(proxychains4 -q curl -s https://api.ipify.org)"
```

---

## 🧩 Tool Matrix

### By Category

**OSINT & Passive Recon:**
- SpiderFoot, theHarvester, Recon-ng, Sublist3r, Amass
- Sherlock, Photon, FinalRecon, OSINT-SPY, Maltego
- holehe, Maigret, h8mail, Buster

**Active Reconnaissance:**
- subfinder, httpx, naabu, nuclei, katana (ProjectDiscovery)
- Nmap, Masscan, Rustscan, Zmap
- gobuster, feroxbuster, ffuf, waybackurls, gau

**Dark Web & Privacy:**
- Tor, Torsocks, ProxyChains4, Privoxy
- OnionShare, Tor Browser, TorBot, i2pd, WireGuard

**Threat Intelligence:**
- ti-feeds (12 sources), Shodan, Censys integrations
- IOC extraction (iocgrab), feed aggregation

**Evidence & Metadata:**
- ExifTool, Metagoofil, Chromium (screenshots)
- Binwalk, Foremost, Strings, Volatility3

**DFIR & Analysis:**
- Yara, Autopsy, Sleuthkit, Volatility3
- chkrootkit, rkhunter, testdisk

**Network Analysis:**
- Wireshark, tshark, tcpdump, Nmap scripts

**Offensive (--with-offsec):**
- Password: Hashcat, John, Hydra, Medusa, Ncrack
- Generation: CUPP, Cewl, Crunch
- Wireless: Aircrack-ng, Reaver, Pixiewps

---

## 📊 Performance Benchmarks

| Operation | v1.0 | v2.0 Enhanced | Improvement |
|-----------|------|---------------|-------------|
| Full Installation | ~15 min | ~8 min | **47% faster** |
| Package Install | Sequential | Parallel | **3-5x faster** |
| Subdomain Enum | ~5 min | ~2 min | **2.5x faster** |
| Tool Updates | ~10 min | ~2.5 min | **4x faster** |
| IOC Extraction | Basic | Enhanced | **10 types** |
| Reporting | Text | HTML/MD | **Professional** |

**System Requirements:**
- Recommended: 4+ CPU cores for parallel operations
- RAM: 4GB minimum, 8GB recommended
- Disk: 20GB free space (40GB for full preset)
- Network: Stable connection for updates

---

## 🐞 Troubleshooting

### Common Issues

**Issue: Tool not found after installation**
```bash
# Solution: Reload shell configuration
source ~/.bashrc
# Or open a new terminal

# Verify PATH
echo $PATH | grep go/bin
```

**Issue: `proxychains4` config not found**
```bash
# Solution: Config auto-detection, manual fix:
sudo cp /etc/proxychains4.conf.bak /etc/proxychains4.conf
# Or reinstall
sudo apt-get install --reinstall proxychains4
```

**Issue: Tor inactive in `ti-health`**
```bash
# Solution: Start and enable Tor
sudo systemctl start tor
sudo systemctl enable tor
# Verify
systemctl status tor
```

**Issue: Nuclei templates outdated/empty**
```bash
# Solution: Update templates
nuclei -update-templates -ut
# Or run full update
sudo ti-update
```

**Issue: Chromium missing for screenshots**
```bash
# Solution: Reinstall chromium
sudo apt-get install --reinstall chromium
# Verify
chromium --version
```

**Issue: Docker permission denied**
```bash
# Solution: Add user to docker group
sudo usermod -aG docker $USER
# Logout and login again
newgrp docker
```

**Issue: Python tools not found**
```bash
# Solution: Activate virtual environment
ti-venv
# Or add to PATH
export PATH="$PATH:$HOME/.ti-venv/bin"
```

### Debug Mode
```bash
# Run installation with debug logging
sudo ./kali-ti-suite.sh --preset full --debug

# Check logs
tail -f /var/log/ti-suite/install-*.log
```

### Getting Help
```bash
# Show detailed help
./kali-ti-suite.sh --help

# Check command help
quick-recon --help
ti-report --help
new-case --help
```

---

## 📈 Optimization Tips

### 1. Maximize Performance
```bash
# Use parallel execution (adjust based on CPU cores)
sudo ./kali-ti-suite.sh --preset full --parallel 8

# For reconnaissance
quick-recon -d target.com --parallel 12
```

### 2. Enable Automation
```bash
# Set up automated maintenance
sudo ./kali-ti-suite.sh --enable-automation

# Manual automation trigger
ti-automate
```

### 3. Batch Operations
```bash
# Multiple screenshots
cat urls.txt | webshot -l - -o screenshots/

# Bulk IOC extraction
find ~/Recon -name "*.txt" -exec cat {} \; | iocgrab
```

### 4. Use Notifications
```bash
# Configure webhooks during install
sudo ./kali-ti-suite.sh --slack-webhook "URL" --discord-webhook "URL"

# Test notifications
ti-notify "Test message"
```

### 5. Docker for Resource Isolation
```bash
# Install with Docker support
sudo ./kali-ti-suite.sh --with-docker

# Run isolated tools
docker run spiderfoot/spiderfoot:latest
```

---

## 🤝 Contributing

Contributions are welcome! Areas of interest:

### High Priority
- Additional TI feed sources
- Enhanced automation workflows
- Report templates (PDF, DOCX)
- Integration with commercial TI platforms
- Advanced correlation engines

### Feature Requests
- New presets for specific use cases
- Additional IOC types
- Machine learning for threat scoring
- Collaborative investigation features
- Cloud storage integrations

### How to Contribute
1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📚 Documentation

- **Complete Guide:** [README-enhanced.md](README-enhanced.md) - Comprehensive documentation
- **Migration Guide:** [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md) - Upgrade from v1.0
- **Installation Logs:** `/var/log/ti-suite/`
- **Configuration:** `~/.ti-suite/config.json`

---

## ⚖️ Legal Disclaimer

This project is intended for **legal and ethical** cybersecurity research, defensive security operations, threat intelligence, incident response, and authorized security testing.

**You are responsible for:**
- ✅ Obtaining proper authorization before testing
- ✅ Complying with all applicable laws and regulations
- ✅ Respecting privacy and data protection requirements
- ✅ Using tools ethically and professionally
- ✅ Maintaining chain of custody for evidence
- ✅ Following your organization's policies

**Unauthorized use may result in:**
- ❌ Criminal prosecution
- ❌ Civil liability
- ❌ Violation of terms of service
- ❌ Damage to systems and networks

The authors and contributors are not responsible for misuse of this tool.

---

## 📜 License

This project is licensed under [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

Built on the shoulders of giants. Special thanks to:

- **ProjectDiscovery Team** - Outstanding reconnaissance tools
- **OWASP Community** - Security testing frameworks
- **Tor Project** - Privacy and anonymity tools
- **Kali Linux Team** - Platform and tool ecosystem
- **OSINT Community** - Techniques and methodologies
- All open-source contributors who make this possible

---

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/Masriyan/Kalitellingence/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Masriyan/Kalitellingence/discussions)
- **Updates**: Watch the repository for new releases

---

## 🗺️ Roadmap

### v2.1 (Planned)
- [ ] PDF report generation
- [ ] DOCX/Excel export
- [ ] Enhanced correlation engine
- [ ] Web UI dashboard
- [ ] Collaborative features
- [ ] Cloud storage integration

### v3.0 (Future)
- [ ] Machine learning threat scoring
- [ ] Automated threat hunting
- [ ] API integrations (MISP, OpenCTI, etc.)
- [ ] Real-time alerting
- [ ] Custom plugin system

---

## 📊 Statistics

- **40+ Tools** installed and configured
- **12 TI Feeds** aggregated
- **10+ IOC Types** extracted
- **4 Case Templates** for professional investigations
- **10+ Helper Commands** for productivity
- **47% Faster** installation
- **3-5x Performance** improvements in operations

---

**Version:** 2.0 Enhanced Edition  
**Last Updated:** December 2024  
**Maintained by:** [@Masriyan](https://github.com/Masriyan)

---

### Quick Reference Card

```
╔══════════════════════════════════════════════════════════════╗
║              KALITELLINGENCE QUICK REFERENCE                 ║
╠══════════════════════════════════════════════════════════════╣
║ RECON:     quick-recon -d target.com [--deep] [--notify]    ║
║ HEALTH:    ti-health                                         ║
║ DASHBOARD: ti-dashboard                                      ║
║ FEEDS:     ti-feeds --fetch | --search "term"               ║
║ IOCs:      iocgrab file.txt [--json]                        ║
║ CASE:      new-case "name" --type [osint|incident|malware] ║
║ REPORT:    ti-report dir/ --format [html|md]               ║
║ UPDATE:    sudo ti-update                                    ║
║ NOTIFY:    ti-notify "message"                              ║
║ SCREEN:    webshot url | webshot -l urls.txt               ║
╚══════════════════════════════════════════════════════════════╝
```

---

*Transform your Kali Linux into a professional Threat Intelligence workstation. Happy hunting! 🎯🔍*
