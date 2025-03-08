#!/bin/bash
# Bash Script to Set Up Kali Linux for Threat Intelligence & Dark Web Investigations
# Ensure this script is run as root (use sudo) to install packages and modify system files.

set -e  # Exit immediately if a command exits with a non-zero status.

echo "[*] Updating system packages..."
apt-get update && apt-get upgrade -y

echo "[*] Installing essential tools via apt..."
apt-get install -y spiderfoot theharvester maltego recon-ng sublist3r sherlock \
                   tor onionshare torsocks proxychains openvpn \
                   nmap masscan amass hashcat john hydra cupp \
                   exiftool metagoofil email2phonenumber ufw

echo "[*] Installing Python tools via pip (Holehe, Knockpy)..."
apt-get install -y python3-pip  # Ensure pip3 is available
pip3 install --upgrade pip  # update pip itself
pip3 install holehe knock-subdomains  # 'holehe' for social media OSINT, 'knock-subdomains' provides knockpy

echo "[*] Cloning and setting up TorBot (Dark Web OSINT crawler)..."
git clone https://github.com/DedSecInside/TorBot.git /opt/TorBot || echo "TorBot already cloned."
pip3 install -r /opt/TorBot/requirements.txt
# Make TorBot easier to run:
ln -sf /opt/TorBot/main.py /usr/local/bin/torbot  && chmod +x /usr/local/bin/torbot

echo "[*] Configuring ProxyChains to route traffic through Tor..."
# Enable dynamic chaining, disable strict chaining, enable proxy DNS, and set Tor SOCKS5 proxy
sed -i 's/^#dynamic_chain/dynamic_chain/' /etc/proxychains.conf
sed -i 's/^strict_chain/#strict_chain/' /etc/proxychains.conf
sed -i 's/^#proxy_dns/proxy_dns/' /etc/proxychains.conf
# Ensure the proxy list has Tor's default SOCKS5 entry:
sed -i 's/^# socks5/socks5/' /etc/proxychains.conf  || echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf

echo "[*] Enabling Tor and OpenVPN services to start at boot..."
systemctl enable tor || echo "Tor service enable failed (maybe already enabled)."
systemctl enable openvpn || true  # don't fail if no config; just ensure service is installed

echo "[*] Setting up investigation data directories..."
# Determine non-root user (if script run via sudo by a normal user)
if [ "$SUDO_USER" ]; then 
    USER_HOME=$(eval echo ~${SUDO_USER}) 
else 
    USER_HOME="$HOME" 
fi
mkdir -p "$USER_HOME/OSINT" "$USER_HOME/DarkWeb" "$USER_HOME/Recon" \
         "$USER_HOME/Passwords" "$USER_HOME/Metadata" "$USER_HOME/SocialMedia" "$USER_HOME/Logs"

echo "[*] Adding convenient aliases to ~/.bashrc ..."
ALIAS_FILE="$USER_HOME/.bashrc"
# Define aliases for common tools if not already present
grep -qxF 'alias sf=' "$ALIAS_FILE" || echo "alias sf='spiderfoot -l 127.0.0.1:5001'" >> "$ALIAS_FILE"     # launch SpiderFoot UI on localhost
grep -qxF 'alias recon=' "$ALIAS_FILE" || echo "alias recon='recon-ng'" >> "$ALIAS_FILE"
grep -qxF 'alias th=' "$ALIAS_FILE" || echo "alias th='theHarvester'" >> "$ALIAS_FILE"
grep -qxF 'alias pc=' "$ALIAS_FILE" || echo "alias pc='proxychains'" >> "$ALIAS_FILE"
# (Add more aliases as needed)

echo "[*] Hardening network settings (enabling UFW firewall)..."
ufw default deny incoming && ufw default allow outgoing
ufw --force enable  # enable UFW without interactive prompt

echo "[*] Enabling persistent bash history logging..."
# Configure immediate history append so that commands are logged even if the shell exits unexpectedly
BASHRC_SYS="/etc/bash.bashrc"
grep -qxF 'shopt -s histappend' "$BASHRC_SYS" || echo 'shopt -s histappend' >> "$BASHRC_SYS"
grep -qxF 'PROMPT_COMMAND="history -a;' "$BASHRC_SYS" || echo 'PROMPT_COMMAND="history -a;$PROMPT_COMMAND"' >> "$BASHRC_SYS"

echo "[+] Environment setup complete. You may need to open a new shell to load aliases."
