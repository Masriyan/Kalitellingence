# Kalitelligence v3.0 - New Features Documentation

## 🎉 What's New in Version 3.0

Kalitelligence v3.0 introduces enterprise-grade features to enhance your threat intelligence operations with automation, API integration, and advanced analytics.

---

## 📋 Table of Contents

1. [REST API Server](#rest-api-server)
2. [Terminal UI Dashboard](#terminal-ui-dashboard)
3. [IOC Enrichment](#ioc-enrichment)
4. [Export Tools](#export-tools)
5. [Playbook Automation](#playbook-automation)
6. [Installation](#installation)
7. [Usage Examples](#usage-examples)
8. [API Reference](#api-reference)

---

## 🌐 REST API Server

### Overview
A production-ready REST API that provides programmatic access to all Kalitelligence features. Perfect for integration with SIEMs, SOAR platforms, and custom applications.

### Features
- **OpenAPI/Swagger Documentation** - Interactive API docs at `/docs`
- **CORS Support** - Cross-origin requests enabled
- **Async Operations** - Background task processing
- **Authentication Ready** - Framework for API key authentication
- **Health Checks** - System monitoring endpoints

### Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select option 1 or 6 (All Features)
```

Or manually:
```bash
sudo systemctl start ti-api
sudo systemctl enable ti-api
```

### Endpoints

#### Health Check
```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "timestamp": "2024-01-15T10:30:00"
}
```

#### Extract IOCs from Text
```bash
curl -X POST http://localhost:8080/api/v1/ioc/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Malicious IP: 192.168.1.100, Domain: evil.com, Hash: abc123...",
    "ioc_types": ["ipv4", "domain", "md5"]
  }'
```

#### Start Reconnaissance
```bash
curl -X POST http://localhost:8080/api/v1/recon/start \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "deep": true,
    "screenshot": true,
    "parallel": 8
  }'
```

#### List Cases
```bash
curl http://localhost:8080/api/v1/cases
```

#### Create Case
```bash
curl -X POST http://localhost:8080/api/v1/cases \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Campaign Investigation",
    "case_type": "incident",
    "client": "ACME Corp",
    "ticket": "INC-2024-001"
  }'
```

#### Search Threat Feeds
```bash
curl "http://localhost:8080/api/v1/feeds/search?query=ransomware"
```

#### Get Statistics
```bash
curl http://localhost:8080/api/v1/stats
```

### Configuration
Edit `/opt/ti-api/main.py` to customize:
- Port (default: 8080)
- CORS origins
- Rate limiting
- Authentication

---

## 🖥️ Terminal UI Dashboard

### Overview
A beautiful, real-time terminal-based dashboard using Rich library for monitoring cases, recon jobs, and system statistics.

### Features
- **Live Updates** - Real-time data refresh
- **Color-Coded Panels** - Easy visual scanning
- **System Metrics** - Disk, uptime, resource usage
- **Case Management** - View active investigations
- **Recon Monitoring** - Track ongoing scans

### Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select option 2 or 6 (All Features)
```

### Usage
```bash
ti-tui
```

### Display
```
┌─────────────────────────────────────────────────────────────┐
│ 🎯 Kalitelligence Dashboard        2024-01-15 10:30:00     │
├──────────────────┬──────────────────────────────────────────┤
│ 📁 Active Cases  │  📊 System Stats                         │
│ CASE-2024-001    │  Disk Used: 45 GB (62%)                  │
│ CASE-2024-002    │  Disk Free: 28 GB                        │
│ CASE-2024-003    │  Uptime: up 2 days, 3 hours              │
│                  │                                          │
│ 🔍 Recent Recon  │  Total Cases: 15                         │
│ example.com      │  Total Recon Jobs: 47                    │
│ test.org         │                                          │
│ target.net       │                                          │
└──────────────────┴──────────────────────────────────────────┘
│ Commands: q=Quit | r=Refresh | c=New Case | s=Stats         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 IOC Enrichment

### Overview
Automatically enrich Indicators of Compromise with threat intelligence from VirusTotal, Shodan, and other sources. Calculate risk scores for prioritization.

### Features
- **Multi-Source Enrichment** - VT, Shodan, more coming
- **Risk Scoring** - 0-100 score with severity levels
- **Multiple IOC Types** - IPs, domains, hashes, emails
- **JSON Output** - Easy integration with other tools
- **API Key Management** - Store keys in config

### Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select option 3 or 6 (All Features)
```

### Configure API Keys
```bash
# Edit config file
nano ~/.ti-suite/config.json

# Add your keys:
{
  "vt_api_key": "YOUR_VIRUSTOTAL_KEY",
  "shodan_api_key": "YOUR_SHODAN_KEY"
}
```

### Usage

#### Single IOC Enrichment
```bash
ti-enrich 192.168.1.100 -t ipv4
```

**Output:**
```
============================================================
IOC: 192.168.1.100 (ipv4)
Timestamp: 2024-01-15T10:30:00
Risk Score: 75/100 (CRITICAL)

VirusTotal:
  Detected: {'malicious': 8, 'suspicious': 2, 'clean': 65}
  Reputation: -84

Shodan:
  Organization: Example ISP
  Country: United States
  Open Ports: 15
  Vulnerabilities: 3
============================================================
```

#### JSON Output
```bash
ti-enrich evil.com -t domain -j
```

**Output:**
```json
{
  "ioc": "evil.com",
  "type": "domain",
  "timestamp": "2024-01-15T10:30:00",
  "virustotal": {
    "detected": {"malicious": 12, "suspicious": 3},
    "reputation": -92
  },
  "risk_score": 85,
  "risk_level": "critical"
}
```

#### With Custom API Keys
```bash
ti-enrich abc123... -t sha256 --vt-key YOUR_KEY
```

### Supported IOC Types
- `ipv4`, `ipv6`
- `domain`
- `url`
- `md5`, `sha1`, `sha256`
- `email`

### Risk Score Calculation
| Score Range | Level | Action |
|------------|-------|--------|
| 75-100 | Critical | Immediate investigation |
| 50-74 | High | Priority review |
| 25-49 | Medium | Monitor closely |
| 0-24 | Low | Informational |

---

## 📤 Export Tools

### Overview
Export case data, IOCs, and threat intelligence in multiple formats including STIX 2.1 for sharing with other security tools.

### Features
- **Multiple Formats** - JSON, CSV, XML, STIX
- **Bulk Export** - Export all cases or specific ones
- **STIX 2.1 Support** - Industry-standard threat intel format
- **Automated Timestamps** - Versioned exports

### Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select option 4 or 6 (All Features)
```

### Usage

#### Export All Cases
```bash
ti-export cases -o all-cases.json
```

#### Export Specific Case
```bash
ti-export cases -c CASE-2024-001 -o case-001.json
```

#### Export IOCs as CSV
```bash
ti-export iocs -f csv -o iocs.csv
```

#### Export as STIX Bundle
```bash
ti-export stix -o threat-intel.stix.json
```

**STIX Output:**
```json
{
  "type": "bundle",
  "id": "bundle--20240115-103000",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--kalitelligence",
      "created": "2024-01-15T10:30:00Z",
      "modified": "2024-01-15T10:30:00Z",
      "name": "Kalitelligence TI Suite",
      "identity_class": "system"
    }
  ]
}
```

### Supported Commands
| Command | Description | Formats |
|---------|-------------|---------|
| `cases` | Export case metadata | JSON |
| `iocs` | Export extracted IOCs | JSON, CSV |
| `stix` | Export STIX bundle | STIX JSON |

---

## ⚙️ Playbook Automation

### Overview
Automate repetitive tasks with Ansible playbooks for reconnaissance, IOC monitoring, and report generation.

### Features
- **Pre-built Playbooks** - Recon, IOC monitoring, daily reports
- **Custom Playbooks** - Create your own automation
- **Variable Support** - Parameterize your workflows
- **Scheduled Execution** - Run via cron or CI/CD

### Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select option 5 or 6 (All Features)
```

### Pre-built Playbooks

#### Reconnaissance Automation
```bash
ti-playbook recon --vars domain=example.com
```

This playbook will:
1. Create output directory
2. Run subdomain enumeration (subfinder)
3. Perform port scanning (naabu)
4. HTTP probing (httpx)
5. Generate summary report

#### IOC Monitoring
```bash
ti-playbook ioc-monitor --vars 'iocs=["evil.com", "bad.org", "192.168.1.100"]'
```

Enriches multiple IOCs and saves results to JSON.

#### Daily Report Generation
```bash
ti-playbook daily-report
```

Generates daily HTML report of all recon activities.

### Custom Playbooks

Create `/opt/ti-playbooks/custom.yml`:
```yaml
---
- name: Custom TI Workflow
  hosts: localhost
  connection: local
  
  vars:
    target: "{{ domain }}"
  
  tasks:
    - name: Run reconnaissance
      shell: quick-recon -d {{ target }} --deep
    
    - name: Extract IOCs
      shell: iocgrab ~/Recon/{{ target }}/report.md -o iocs.csv
    
    - name: Enrich IOCs
      shell: ti-enrich $(cat iocs.csv) -t domain -j > enriched.json
```

Run custom playbook:
```bash
ti-playbook custom -f /opt/ti-playbooks/custom.yml --vars domain=target.com
```

### Integration with CI/CD

Example GitHub Actions workflow:
```yaml
name: Daily TI Scan
on:
  schedule:
    - cron: '0 2 * * *'

jobs:
  recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Recon
        run: |
          ti-playbook recon --vars domain=${{ secrets.TARGET_DOMAIN }}
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: recon-results
          path: ~/Recon/
```

---

## 🚀 Installation

### Quick Install (All Features)
```bash
# After running main kalitelligence.sh installation
sudo ./kalitelligence-v3-features.sh
# Select option 6 (All Features)
```

### Individual Feature Installation
```bash
sudo ./kalitelligence-v3-features.sh
# Select options 1-5 individually
```

### Requirements
- Python 3.8+
- pip packages: fastapi, uvicorn, rich, requests, ansible
- Root/sudo access
- Kali Linux (recommended) or Ubuntu/Debian

### Post-Installation Verification

Check all commands are available:
```bash
which ti-api ti-tui ti-enrich ti-export ti-playbook
```

Check API server status:
```bash
systemctl status ti-api
```

Test API endpoint:
```bash
curl http://localhost:8080/health
```

---

## 📖 Usage Examples

### Scenario 1: Automated Phishing Investigation

```bash
# 1. Create case
new-case "Phishing Campaign Q1" --type incident --client "ACME Corp"

# 2. Extract IOCs from email headers
cat email_headers.txt | iocgrab -o phishing-iocs.csv

# 3. Enrich IOCs
while IFS=, read -r type value count; do
  [[ "$type" == "type" ]] && continue  # Skip header
  ti-enrich "$value" -t "$type" -j >> enriched.json
done < phishing-iocs.csv

# 4. Run reconnaissance on malicious domains
ti-playbook recon --vars domain=phishing-domain.com

# 5. Generate report
ti-report ~/Cases/CASE-2024-phishing -o final-report.html

# 6. Export for sharing
ti-export cases -c CASE-2024-phishing -o case-export.json
ti-export stix -o threat-intel.stix.json
```

### Scenario 2: Continuous Monitoring

```bash
# Add to crontab for hourly IOC enrichment
0 * * * * /usr/local/bin/ti-playbook ioc-monitor --vars 'iocs=["known-bad.com"]'

# Daily report generation
0 8 * * * /usr/local/bin/ti-playbook daily-report

# Weekly tool updates
0 3 * * 0 /usr/local/bin/ti-update
```

### Scenario 3: API Integration with SIEM

```python
import requests
import json

# Extract IOCs from SIEM alert
alert_text = get_siem_alert()
response = requests.post(
    "http://localhost:8080/api/v1/ioc/extract",
    json={"text": alert_text}
)
iocs = response.json()

# Enrich each IOC
for ioc in iocs['iocs'].get('domain', []):
    enrichment = requests.post(
        "http://localhost:8080/api/v1/ioc/enrich",
        json={"ioc": ioc, "type": "domain"}
    )
    
    # Send high-risk IOCs to SOAR
    if enrichment.json()['risk_score'] >= 75:
        trigger_soar_playbook(enrichment.json())
```

---

## 🔗 API Reference

### Base URL
```
http://localhost:8080
```

### Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/system` | System information |
| GET | `/api/v1/stats` | Suite statistics |
| POST | `/api/v1/ioc/extract` | Extract IOCs from text |
| POST | `/api/v1/recon/start` | Start recon job |
| GET | `/api/v1/cases` | List cases |
| POST | `/api/v1/cases` | Create case |
| GET | `/api/v1/feeds` | Get TI feeds |
| GET | `/api/v1/feeds/search` | Search feeds |

### Interactive Documentation
Visit `http://localhost:8080/docs` for Swagger UI with:
- Try-it-out functionality
- Request/response schemas
- Authentication testing
- Code generation

---

## 🛠️ Troubleshooting

### API Server Won't Start
```bash
# Check logs
journalctl -u ti-api -f

# Verify port availability
netstat -tlnp | grep 8080

# Restart service
sudo systemctl restart ti-api
```

### TUI Display Issues
```bash
# Ensure terminal supports colors
export TERM=xterm-256color

# Reinstall dependencies
source ~/.ti-venv/bin/activate
pip install --upgrade rich textual
```

### IOC Enrichment Fails
```bash
# Verify API keys
cat ~/.ti-suite/config.json

# Test connectivity
curl -H "x-apikey: YOUR_KEY" https://www.virustotal.com/api/v3/domains/google.com
```

### Playbook Errors
```bash
# Run with verbose output
ansible-playbook /opt/ti-playbooks/recon.yml -vvv

# Check Ansible version
ansible --version

# Reinstall Ansible
sudo apt-get install --reinstall ansible
```

---

## 📝 Changelog

### v3.0.0 (2024)
- ✨ **NEW**: REST API server with OpenAPI documentation
- ✨ **NEW**: Terminal UI dashboard with live updates
- ✨ **NEW**: IOC enrichment with VirusTotal and Shodan
- ✨ **NEW**: Export tools with STIX 2.1 support
- ✨ **NEW**: Ansible playbook automation
- 🔧 Enhanced error handling across all tools
- 📚 Comprehensive API documentation
- ⚡ Performance improvements

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Submit pull request
4. Update documentation

---

## 📄 License

MIT License - See LICENSE file for details

---

## 📞 Support

- Documentation: `/opt/ti-suite/README.md`
- Issues: GitHub Issues
- API Docs: `http://localhost:8080/docs`

---

**Happy Hunting! 🎯**
