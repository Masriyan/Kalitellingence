![Kalitellingence - Make Over Your Kali Linux Into Threat Intelligence Banner](https://github.com/Masriyan/Kalitellingence/blob/main/image.png)
# Kalitellingence - Make Over Your Kali Linux Into Threat Intelligence

This repository contains a **Bash script** to automate the setup of **Kali Linux** for **Threat Intelligence** tasks and **Dark Web investigations**. The script installs and configures essential tools for OSINT, reconnaissance, anonymity, and data collection, ensuring a fully operational environment for cybersecurity professionals.

## Features

✅ **OSINT Tools**: SpiderFoot, theHarvester, Maltego, Recon-ng, Sublist3r, Sherlock, Holehe  
✅ **Dark Web Tools**: Tor, OnionShare, Torsocks, TorBot  
✅ **Reconnaissance**: Nmap, Masscan, Knockpy, Amass  
✅ **Password Cracking**: Hashcat, John the Ripper, Hydra, CUPP  
✅ **Metadata Analysis**: ExifTool, Metagoofil  
✅ **Social Media OSINT**: Email2Phonenumber  
✅ **Anonymity Configuration**: Tor, ProxyChains, OpenVPN  
✅ **System Hardening**: Firewall (UFW), bash history logging  
✅ **Automated Setup**: Services auto-start on boot, aliases for quick access  

## Installation

### **1. Clone the Repository**
```bash
git clone https://github.com/Masriyan/Kalitellingence.git
cd Kalitellingence
```

### **2. Make the Script Executable**
```bash
chmod +x kalitelligence.sh
```

### **3. Run the Script**
Execute the script with **root privileges**:
```bash
sudo ./kalitelligence.sh
```

This will install and configure all required tools automatically.

## Tools Installed & Configured

### **1. OSINT Tools**
- **SpiderFoot** – Automated OSINT collection & analysis
- **theHarvester** – Email, domain, and username reconnaissance
- **Maltego** – Data visualization & link analysis tool
- **Recon-ng** – Web-based reconnaissance framework
- **Sublist3r** – Subdomain enumeration
- **Sherlock** – Username reconnaissance across social media platforms
- **Holehe** – Email OSINT for social media accounts
- **email2phonenumber** – Find phone numbers linked to email addresses

### **2. Dark Web & Anonymity Tools**
- **Tor** – Anonymity network
- **OnionShare** – Securely share files over Tor
- **Torsocks** – Tunnel any application through Tor
- **ProxyChains** – Route any network traffic through Tor
- **OpenVPN** – VPN support for additional security
- **TorBot** – Automated dark web crawler

### **3. Network Reconnaissance**
- **Nmap** – Network scanner
- **Masscan** – Internet-wide port scanning
- **Knockpy** – Subdomain enumeration
- **Amass** – Advanced domain reconnaissance

### **4. Password Cracking & OSINT**
- **Hashcat** – GPU-based password cracking
- **John the Ripper** – Offline password cracking
- **Hydra** – Online brute force attacks
- **CUPP** – Custom wordlist generator

### **5. Metadata Analysis**
- **ExifTool** – Extract metadata from images & files
- **Metagoofil** – Extract metadata from public documents

## Configuration & Optimization

### **1. ProxyChains Configuration**
The script configures **ProxyChains** to use **Tor** for anonymity. To use a tool through Tor, prefix it with `proxychains`:
```bash
proxychains nmap -sT -Pn example.com
```

### **2. Firewall & Security Settings**
The script enables **UFW (Uncomplicated Firewall)**:
```bash
sudo ufw status
```

### **3. Directory Organization**
To keep intelligence data structured, the script creates the following directories:
```bash
~/OSINT/
~/DarkWeb/
~/Recon/
~/Passwords/
~/Metadata/
~/SocialMedia/
~/Logs/
```

## Usage Examples

### **1. Run SpiderFoot**
```bash
sf
```
Access the UI at: **http://127.0.0.1:5001**

### **2. Run theHarvester**
```bash
theHarvester -d example.com -b google
```

### **3. Scan with Nmap via Tor**
```bash
proxychains nmap -sT -Pn example.com
```

### **4. Run Sherlock for Username Investigation**
```bash
sherlock username
```

### **5. Run TorBot for Dark Web Crawling**
```bash
torbot -u http://exampleonion.onion
```

## Verification
After running the script, verify installations:
```bash
spiderfoot -h
recon-ng
proxychains curl -s https://check.torproject.org | grep -i "Congratulations"
nmap --version
```

## Contributions
Feel free to contribute by submitting issues or pull requests.

## Disclaimer
**This script is for legal and ethical cybersecurity research only.** Do not use it for unauthorized activities. The author assumes no responsibility for misuse.

## License
This project is licensed. See `LICENSE` for details.
