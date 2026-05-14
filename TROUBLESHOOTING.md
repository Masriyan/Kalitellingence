# Troubleshooting Guide

## Common Issues and Solutions

This guide helps you resolve common issues encountered when using Kalitelligence.

---

## Installation Issues

### Issue: Script fails with "Permission denied"

**Symptoms:**
```bash
bash: ./kalitelligence.sh: Permission denied
```

**Solution:**
```bash
chmod +x kalitelligence.sh
sudo ./kalitelligence.sh --preset passive
```

---

### Issue: "Run as root" error

**Symptoms:**
```bash
[ERROR] Run as root (e.g., sudo $0)
```

**Solution:**
```bash
sudo ./kalitelligence.sh --preset passive
```

---

### Issue: Installation hangs during package installation

**Symptoms:**
- Script appears stuck at "Installing packages..."
- No progress for several minutes

**Causes:**
1. Slow network connection
2. Package repository issues
3. Large number of packages to install

**Solutions:**

**Option 1: Wait it out**
- Some installations can take 5-10 minutes on slow connections

**Option 2: Check network**
```bash
ping -c 4 archive.kali.org
```

**Option 3: Update package lists manually**
```bash
sudo apt update
sudo ./kalitelligence.sh --preset passive
```

**Option 4: Reduce parallel jobs**
```bash
sudo ./kalitelligence.sh --preset passive --parallel 2
```

---

### Issue: Disk space running low

**Symptoms:**
```bash
[ERROR] Not enough disk space
```

**Solution:**
```bash
# Check available space
df -h

# Clean up package cache
sudo apt clean

# Remove unused kernels
sudo apt autoremove --purge

# Check large files
sudo du -sh /* | sort -h | tail -10
```

**Minimum Requirements:**
- Passive preset: 5GB free space
- Full preset: 15GB free space
- With Docker: Additional 5GB

---

### Issue: Tool installation failures

**Symptoms:**
```bash
[WARN] Failed to install tool-name
```

**Solutions:**

**Check which tools failed:**
```bash
grep -i "failed" /var/log/ti-suite/install-*.log
```

**Retry specific tool category:**
```bash
# Re-run with custom preset to skip already installed tools
sudo ./kalitelligence.sh --preset custom --with-osint
```

**Manual installation:**
```bash
# Example for failed Python tool
pip3 install tool-name

# Example for failed Go tool
go install github.com/user/tool@latest
```

---

## Runtime Issues

### Issue: Command not found after installation

**Symptoms:**
```bash
bash: ti-dashboard: command not found
```

**Solution:**
```bash
# Reload bash configuration
source ~/.bashrc

# Or start a new terminal session

# Verify aliases are loaded
alias | grep ti-
```

---

### Issue: Tor not connecting

**Symptoms:**
- `tor` service fails to start
- Cannot access .onion sites

**Solution:**
```bash
# Check Tor status
systemctl status tor

# Restart Tor
sudo systemctl restart tor

# Check Tor logs
journalctl -u tor -n 50

# Verify Tor circuit
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org
```

**If still failing:**
```bash
# Reinstall Tor
sudo apt install --reinstall tor torsocks

# Check AppArmor
sudo aa-status | grep tor
```

---

### Issue: Python virtual environment errors

**Symptoms:**
```bash
ModuleNotFoundError: No module named 'requests'
```

**Solution:**
```bash
# Activate the virtual environment
source ~/OSINT/venv/bin/activate

# Install missing packages
pip install requests

# Or reinstall all requirements
pip install -r ~/OSINT/requirements.txt
```

---

### Issue: SQLite database locked

**Symptoms:**
```bash
sqlite3.Error: database is locked
```

**Solution:**
```bash
# Find processes using the database
lsof ~/OSINT/feeds.db

# Kill blocking processes
kill <PID>

# Or wait for process to complete

# If persistent, remove lock file
rm -f ~/OSINT/feeds.db-journal
```

---

### Issue: Reconnaissance timeout

**Symptoms:**
- `quick-recon` hangs or times out
- Incomplete results

**Solutions:**

**Increase timeout:**
```bash
# Edit the script and increase TIMEOUT value
# Or run with fewer parallel jobs
quick-recon -d target.com --workers 2
```

**Check network connectivity:**
```bash
# Test DNS resolution
dig target.com

# Test HTTP connectivity
curl -I https://target.com
```

**Run tools individually:**
```bash
# Instead of full recon, run specific tools
subfinder -d target.com -o subs.txt
httpx -l subs.txt -status-code
```

---

### Issue: Screenshots not generating

**Symptoms:**
- `webshot` produces empty output
- Screenshot files are 0 bytes

**Solution:**
```bash
# Install/reinstall Chromium
sudo apt install --reinstall chromium

# Install required dependencies
sudo apt install xvfb x11-xkb-utils xfonts-100dpi xfonts-75dpi xfonts-cyrillic xfonts-scalable libcups2-dev libxkbcommon-x11-0

# Test screenshot manually
chromium --headless --screenshot=/tmp/test.png https://example.com

# Check if screenshot was created
ls -lh /tmp/test.png
```

---

### Issue: Notifications not sending

**Symptoms:**
- Slack/Discord notifications not received
- No error messages

**Solution:**
```bash
# Test webhook URL
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message"}' \
  YOUR_WEBHOOK_URL

# Check configuration
cat ~/OSINT/.config/kalitelligence.conf | grep webhook

# Verify network connectivity
curl -I https://hooks.slack.com
curl -I https://discord.com
```

**For Slack:**
- Ensure webhook URL is correct
- Check Slack workspace permissions
- Verify webhook hasn't been revoked

**For Discord:**
- Ensure webhook URL is correct
- Check channel permissions
- Verify webhook hasn't been deleted

---

### Issue: IOC extraction returns nothing

**Symptoms:**
- `iocgrab` produces empty output
- Known IOCs not detected

**Solution:**
```bash
# Verify input file format
cat iocs.txt

# Try with explicit type
iocgrab file.txt --type ip
iocgrab file.txt --type domain

# Check file encoding
file iocs.txt

# Convert to UTF-8 if needed
iconv -f ISO-8859-1 -t UTF-8 iocs.txt > iocs_utf8.txt
iocgrab iocs_utf8.txt
```

---

### Issue: Report generation fails

**Symptoms:**
- `ti-report` exits with error
- Empty or incomplete reports

**Solution:**
```bash
# Check if directory exists
ls -la ~/Recon/target.com/

# Verify report template
ls -la /usr/local/share/kalitelligence/templates/

# Run with debug mode
ti-report ~/Recon/target.com/ --format html --debug

# Check for missing data files
find ~/Recon/target.com/ -name "*.txt" -o -name "*.json"
```

---

### Issue: Dashboard shows incorrect stats

**Symptoms:**
- `ti-dashboard` displays wrong numbers
- Missing case information

**Solution:**
```bash
# Refresh dashboard data
ti-dashboard --refresh

# Clear cache
rm -rf /tmp/ti-dashboard-cache/

# Check data sources
ls -la ~/Cases/
ls -la ~/OSINT/

# Verify database integrity
sqlite3 ~/OSINT/feeds.db "PRAGMA integrity_check;"
```

---

## Update Issues

### Issue: ti-update fails

**Symptoms:**
```bash
[ERROR] Failed to update
```

**Solution:**
```bash
# Manual update
cd /workspace
git pull origin main

# Check for local changes
git status

# If conflicts, reset and reapply
git stash
git pull origin main
git stash pop

# Re-run installer
sudo ./kalitelligence.sh --preset passive
```

---

### Issue: Version mismatch after update

**Symptoms:**
- Old commands still present
- New features not available

**Solution:**
```bash
# Force reload of bash configuration
source ~/.bashrc

# Or restart terminal

# Verify version
grep "Version" kalitelligence.sh

# Clear any cached scripts
hash -r
```

---

## Performance Issues

### Issue: System becomes unresponsive during installation

**Symptoms:**
- High CPU usage
- System lag

**Solution:**
```bash
# Reduce parallel jobs
sudo ./kalitelligence.sh --preset passive --parallel 2

# Monitor resource usage
htop
iotop

# Pause other applications

# Consider adding swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

### Issue: Slow reconnaissance operations

**Symptoms:**
- Recon takes much longer than expected
- Tools timing out

**Solution:**
```bash
# Check network speed
speedtest-cli

# Reduce concurrent workers
quick-recon -d target.com --workers 2

# Skip heavy checks
quick-recon -d target.com --light

# Use cached results when available
quick-recon -d target.com --cached
```

---

## Security Issues

### Issue: Firewall blocking legitimate traffic

**Symptoms:**
- Cannot connect to certain services
- UFW dropping packets

**Solution:**
```bash
# Check UFW status
sudo ufw status verbose

# View denied packets
sudo ufw log read | grep DENY

# Add exceptions
sudo ufw allow out 80/tcp
sudo ufw allow out 443/tcp
sudo ufw allow out 53/udp

# Or disable UFW temporarily (not recommended)
sudo ufw disable
```

---

### Issue: Certificate verification failures

**Symptoms:**
```bash
SSL certificate problem: unable to get local issuer certificate
```

**Solution:**
```bash
# Update CA certificates
sudo apt install --reinstall ca-certificates
sudo update-ca-certificates

# Check system time (certificates are time-sensitive)
date

# If behind proxy, configure proxy settings
export HTTPS_PROXY=http://proxy:port
```

---

## Getting Help

### Check Logs

```bash
# Installation logs
ls -lt /var/log/ti-suite/

# View latest log
tail -100 /var/log/ti-suite/install-*.log

# Search for errors
grep -i "error\|fail" /var/log/ti-suite/*.log
```

### System Information

When reporting issues, include:

```bash
# Kali version
cat /etc/os-release

# Python version
python3 --version

# Bash version
bash --version

# Available disk space
df -h

# Memory
free -h

# Installed tools version
ti-health
```

### Community Resources

- **GitHub Issues**: https://github.com/Masriyan/Kalitellingence/issues
- **GitHub Discussions**: https://github.com/Masriyan/Kalitellingence/discussions
- **Documentation**: See other .md files in this repository

---

## Prevention Tips

1. **Always test in VM first** before production use
2. **Keep system updated** with `sudo apt update && sudo apt upgrade`
3. **Regular backups** of case data and configurations
4. **Monitor disk space** regularly
5. **Review logs** periodically for warnings
6. **Use stable network** connection during installation
7. **Read release notes** before updating

---

**Last Updated**: December 2024  
**Document Version**: 1.0
