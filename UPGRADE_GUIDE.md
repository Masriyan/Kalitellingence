# Kalitelligence v3.0 Upgrade Guide

## 📋 Overview

This guide helps you upgrade from Kalitelligence v2.x to v3.0 with new enterprise features.

---

## 🚀 Quick Upgrade (Recommended)

```bash
# 1. Ensure you have the latest v2.x installation
cd /workspace
sudo ./kalitelligence.sh --preset full

# 2. Run the v3.0 feature installer
sudo ./kalitelligence-v3-features.sh

# 3. Select option 6 (All Features) for complete installation
```

---

## 📦 What's New in v3.0

### Major Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **REST API** | FastAPI-based server with OpenAPI docs | Programmatic access, SIEM integration |
| **TUI Dashboard** | Rich-based terminal UI | Real-time monitoring, beautiful interface |
| **IOC Enrichment** | VirusTotal & Shodan integration | Automated threat scoring |
| **Export Tools** | JSON, CSV, STIX 2.1 formats | Easy data sharing |
| **Playbook Automation** | Ansible-based workflows | Repeatable processes |

### New Commands

```bash
ti-api        # Start REST API server
ti-tui        # Launch terminal dashboard
ti-enrich     # Enrich IOCs with threat intel
ti-export     # Export data in multiple formats
ti-playbook   # Run automation playbooks
```

---

## 🔧 Installation Options

### Option 1: Install All Features (Recommended)

```bash
sudo ./kalitelligence-v3-features.sh
# Select: 6) All Features
```

### Option 2: Install Individual Features

```bash
sudo ./kalitelligence-v3-features.sh
# Select individual options:
# 1) REST API Server
# 2) TUI Dashboard
# 3) IOC Enrichment
# 4) Export Tools
# 5) Playbook Automation
```

### Option 3: Silent Installation (Scripted)

```bash
#!/bin/bash
# install-v3-silent.sh

# Install all features non-interactively
source ./kalitelligence-v3-features.sh <<< "6"
```

---

## ⚙️ Configuration

### REST API Configuration

Edit `/opt/ti-api/main.py`:

```python
# Change port (default: 8080)
uvicorn.run(app, host="0.0.0.0", port=8080)

# Add authentication
# Add rate limiting
# Configure CORS origins
```

Manage service:
```bash
sudo systemctl start ti-api
sudo systemctl enable ti-api
sudo systemctl status ti-api
```

### IOC Enrichment API Keys

Edit `~/.ti-suite/config.json`:

```json
{
  "vt_api_key": "YOUR_VIRUSTOTAL_API_KEY",
  "shodan_api_key": "YOUR_SHODAN_API_KEY",
  "slack_webhook": "https://hooks.slack.com/...",
  "discord_webhook": "https://discord.com/api/..."
}
```

Get API keys:
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [Shodan](https://account.shodan.io/register)

### Playbook Customization

Create custom playbooks in `/opt/ti-playbooks/`:

```yaml
---
- name: Custom Workflow
  hosts: localhost
  connection: local
  
  vars:
    target: "{{ domain }}"
  
  tasks:
    - name: Your task
      shell: your-command {{ target }}
```

---

## 📖 Usage Examples

### Example 1: Automated Investigation Workflow

```bash
# 1. Start API server
sudo systemctl start ti-api

# 2. Create case via API
curl -X POST http://localhost:8080/api/v1/cases \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Investigation",
    "case_type": "incident",
    "client": "ACME Corp"
  }'

# 3. Extract IOCs from evidence
cat email_headers.txt | iocgrab -o iocs.csv

# 4. Enrich IOCs
while IFS=, read -r type value count; do
  [[ "$type" == "type" ]] && continue
  ti-enrich "$value" -t "$type" -j >> enriched.json
done < iocs.csv

# 5. Generate report
ti-report ~/Cases/CASE-* -o final-report.html

# 6. Export for sharing
ti-export cases -o cases.json
ti-export stix -o threat-intel.stix.json
```

### Example 2: Continuous Monitoring

Add to crontab (`crontab -e`):

```bash
# Hourly IOC enrichment
0 * * * * /usr/local/bin/ti-playbook ioc-monitor --vars 'iocs=["known-bad.com"]'

# Daily report generation
0 8 * * * /usr/local/bin/ti-playbook daily-report

# Weekly tool updates
0 3 * * 0 /usr/local/bin/ti-update
```

### Example 3: SIEM Integration

Python script for SIEM integration:

```python
import requests

# Extract IOCs from alert
response = requests.post(
    "http://localhost:8080/api/v1/ioc/extract",
    json={"text": siem_alert_text}
)

# Process each IOC
for ioc in response.json()['iocs'].get('domain', []):
    # Enrich
    enrichment = requests.post(
        "http://localhost:8080/api/v1/ioc/enrich",
        json={"ioc": ioc, "type": "domain"}
    )
    
    # Alert on high risk
    if enrichment.json()['risk_score'] >= 75:
        send_to_soar(enrichment.json())
```

---

## 🔍 Verification

After installation, verify all components:

```bash
# Check commands exist
which ti-api ti-tui ti-enrich ti-export ti-playbook

# Test API server
curl http://localhost:8080/health

# Expected output:
# {"status":"healthy","version":"3.0.0","timestamp":"..."}

# Test TUI (interactive)
ti-tui

# Test IOC enrichment
ti-enrich google.com -t domain

# Test export
ti-export cases -o test-export.json

# Test playbook
ti-playbook recon --vars domain=example.com
```

---

## 🛠️ Troubleshooting

### API Server Won't Start

```bash
# Check logs
journalctl -u ti-api -f

# Check port availability
sudo netstat -tlnp | grep 8080

# Restart service
sudo systemctl restart ti-api

# Reinstall dependencies
source ~/.ti-venv/bin/activate
pip install fastapi uvicorn python-multipart pydantic
```

### TUI Display Issues

```bash
# Set terminal type
export TERM=xterm-256color

# Reinstall Rich
source ~/.ti-venv/bin/activate
pip install --upgrade rich textual
```

### IOC Enrichment Fails

```bash
# Verify API keys
cat ~/.ti-suite/config.json

# Test VirusTotal connectivity
curl -H "x-apikey: YOUR_KEY" \
  https://www.virustotal.com/api/v3/domains/google.com

# Check network
ping www.virustotal.com
```

### Playbook Errors

```bash
# Run with verbose output
ansible-playbook /opt/ti-playbooks/recon.yml -vvv

# Check syntax
ansible-playbook /opt/ti-playbooks/recon.yml --syntax-check

# Reinstall Ansible
sudo apt-get install --reinstall ansible
```

---

## 📊 Migration from v2.x

### Backward Compatibility

All v2.x commands remain functional:
- ✅ `quick-recon`
- ✅ `ti-health`
- ✅ `iocgrab`
- ✅ `webshot`
- ✅ `new-case`
- ✅ `ti-feeds`
- ✅ `ti-report`
- ✅ `ti-dashboard`
- ✅ `ti-update`

### New Configuration Structure

v2.x config:
```json
{
  "version": "2.0",
  "preset": "full"
}
```

v3.0 config (backward compatible):
```json
{
  "version": "3.0",
  "preset": "full",
  "vt_api_key": "...",
  "shodan_api_key": "...",
  "api_port": 8080,
  "enable_stix": true
}
```

### Data Migration

No manual migration required! All existing data is automatically compatible:
- Cases in `~/Cases/`
- Recon data in `~/Recon/`
- TI feeds database in `~/OSINT/ti-feeds.db`
- IOCs in `~/OSINT/iocs-*.csv`

---

## 📈 Performance Considerations

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 50 GB |
| CPU | 2 cores | 4+ cores |
| Network | 10 Mbps | 100+ Mbps |

### API Server Tuning

For high-load environments, edit `/opt/ti-api/main.py`:

```python
# Increase workers
uvicorn.run(app, host="0.0.0.0", port=8080, workers=4)

# Add rate limiting
from slowapi import SlowAPI
app.state.limiter = SlowAPI()
```

### Database Optimization

Optimize SQLite database:

```bash
sqlite3 ~/OSINT/ti-feeds.db "VACUUM;"
sqlite3 ~/OSINT/ti-feeds.db "ANALYZE;"
```

---

## 🔐 Security Considerations

### API Security

By default, the API binds to `0.0.0.0` (all interfaces). For production:

1. **Restrict to localhost** (if only local access needed):
   ```python
   uvicorn.run(app, host="127.0.0.1", port=8080)
   ```

2. **Add authentication**:
   ```python
   from fastapi.security import APIKeyHeader
   
   api_key_header = APIKeyHeader(name="X-API-Key")
   
   async def get_api_key(api_key: str = Depends(api_key_header)):
       if api_key != EXPECTED_KEY:
           raise HTTPException(status_code=403)
       return api_key
   ```

3. **Use reverse proxy** (nginx):
   ```nginx
   location /api/ {
       proxy_pass http://127.0.0.1:8080;
       auth_basic "Restricted";
       auth_basic_user_file /etc/nginx/.htpasswd;
   }
   ```

### API Key Storage

Store sensitive keys securely:

```bash
# Set restrictive permissions
chmod 600 ~/.ti-suite/config.json
chown $USER:$USER ~/.ti-suite/config.json

# Or use environment variables
export VT_API_KEY="your-key-here"
export SHODAN_API_KEY="your-key-here"
```

---

## 📚 Additional Resources

- **Full Documentation**: See `FEATURES_V3.md`
- **API Reference**: `http://localhost:8080/docs`
- **Troubleshooting**: See `TROUBLESHOOTING.md`
- **Architecture**: See `ARCHITECTURE.md`

---

## 🆘 Getting Help

1. Check logs: `/var/log/ti-suite/*.log`
2. Review documentation: `/opt/ti-suite/README.md`
3. Test individual components
4. Open GitHub issue with:
   - Error messages
   - Log excerpts
   - Steps to reproduce

---

## ✅ Post-Upgrade Checklist

- [ ] All v3.0 commands installed and working
- [ ] API server starts successfully
- [ ] API keys configured in `~/.ti-suite/config.json`
- [ ] TUI dashboard displays correctly
- [ ] IOC enrichment returns data
- [ ] Export tools create valid files
- [ ] Playbooks execute without errors
- [ ] Existing v2.x workflows still function
- [ ] Cron jobs updated (if using automation)
- [ ] Documentation reviewed

---

**Upgrade Complete! Happy Hunting! 🎯**
