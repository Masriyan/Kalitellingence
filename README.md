![Kalitellingence - Make Over Your Kali Linux Into Threat Intelligence Banner](https://github.com/Masriyan/Kalitellingence/blob/main/image.png)

# Kalitellingence – Make Over Your Kali Linux Into a Threat Intelligence Workstation

Kalitellingence turns a fresh **Kali Linux** into a practical workstation for **Threat Intelligence (TI)**, **OSINT**, **External Attack Surface Management (EASM)**, **Dark-web investigations**, and **light DFIR**—with **safe defaults**, **presets**, and **helper commands** that speed up real work.

> ⚠️ Use only on systems/targets you are **authorized** to assess. Some tools are dual-use.

---

## 🚀 What’s New (vNext)

- **One-shot installer** with **presets**: `passive`, `darkweb`, `easm`, `dfir`, `full`.
- **Strict opt-in** for offensive tools (`--with-offsec`).
- **Helper commands**:
  - `quick-recon` → subdomain → live host → nuclei (low/medium) report.
  - `ti-health` → sanity checks (Tor/proxies/binaries).
  - `ti-update` → apt, pip, ProjectDiscovery, nuclei templates.
  - `iocgrab` → extract URLs/IPs/domains/hashes/emails → CSV.
  - `webshot` → headless screenshot for evidence.
  - `new-case` → chain-of-custody friendly folders scaffold.
  - `ti-feeds` → RSS aggregator → SQLite (CISA, NVD, etc.).
- **Hardening & QoL**: ProxyChains tuned (dynamic_chain + proxy_dns), Tor autostart, optional UFW, persistent bash history, smart aliases.

---

## ✨ Features

- **OSINT & Recon**
  - SpiderFoot, theHarvester, Recon-ng, Sublist3r, Amass
  - ProjectDiscovery suite: **subfinder**, **httpx**, **naabu**, **nuclei**, **katana**
  - dnstwist, sn0int, Nmap, Masscan, Seclists
- **Dark-web & Anonymity**
  - Tor, Torsocks, ProxyChains, OnionShare, Tor Browser launcher, TorBot
- **Evidence & Metadata**
  - ExifTool, Metagoofil, headless Chromium screenshots (`webshot`)
- **Feeds & IOCs**
  - RSS → SQLite (`ti-feeds`), IOC extractor (`iocgrab`)
- **DFIR (preset)**
  - Yara, binwalk, foremost, optional `volatility3`
- **Offensive (opt-in)**
  - Hashcat, John, Hydra, CUPP (enabled only with `--with-offsec`)
- **System Hardening**
  - UFW (deny in / allow out), persistent history, proxy settings

---

## 🧩 Presets

Choose a preset during install to keep things focused:

| Preset    | Focus | Includes |
|---|---|---|
| `passive` (default) | Safe OSINT | OSINT + ProjectDiscovery tools |
| `darkweb` | Tor/Onions | OSINT + Tor/Torsocks/ProxyChains/OnionShare/TorBot |
| `easm` | External Attack Surface | ProjectDiscovery (subfinder/httpx/naabu/nuclei/katana) |
| `dfir` | Light forensics | Yara/binwalk/foremost + core OSINT |
| `full` | Everything (safe by default) | All of the above (offsec still opt-in) |

Offensive tools require **explicit** `--with-offsec`.

---

## 📦 Installation

### 1) Clone the repository
```bash
git clone https://github.com/Masriyan/Kalitellingence.git
cd Kalitellingence
```

### 2) Make the installer executable  
> The new unified script is named **`kali-ti-suite.sh`**.
```bash
chmod +x kali-ti-suite.sh
```

### 3) Run with your preferred preset
```bash
sudo ./kali-ti-suite.sh --preset full            # passive | darkweb | easm | dfir | full
# Optional:
#   --with-offsec          # add hashcat/hydra/john/cupp (explicit opt-in)
#   --no-ufw               # skip firewall hardening
#   --proxy tor            # quick-recon uses ProxyChains/Tor
#   --proxy none           # (default) direct egress for quick-recon
```

> **Upgrading from older script (`kalitelligence.sh`)**  
> You can keep both files, but this README and future updates assume **`kali-ti-suite.sh`**.

---

## 🗂️ Workspace Layout

The installer creates structured folders in your home directory:

```
~/OSINT/        # Findings, feeds.db, IOC CSVs
~/DarkWeb/
~/Recon/        # quick-recon outputs per target/run
~/Passwords/
~/Metadata/
~/SocialMedia/
~/Logs/
~/Cases/        # new-case scaffolds with notes/evidence subfolders
```

---

## 🧰 Helper Commands (after install)

- **Quick recon pipeline**
  ```bash
  quick-recon -d example.com --proxy none   # or: --proxy tor
  # Output: ~/Recon/example.com/YYYYmmdd-HHMMSS/
  #   subs.txt, httpx.txt, nuclei.txt, report.txt
  ```

- **Health & sanity**
  ```bash
  ti-health
  # Checks Tor service, proxychains/torsocks outbound IP, key binaries & versions
  ```

- **Update everything**
  ```bash
  sudo ti-update
  # apt, pip tools, ProjectDiscovery binaries, nuclei templates
  ```

- **IOC extraction**
  ```bash
  iocgrab suspicious.txt
  # -> ~/OSINT/iocs-YYYYmmdd-HHMMSS.csv
  ```

- **Headless screenshot (evidence)**
  ```bash
  webshot "https://target.tld/page"  # outputs screenshot-*.png
  ```

- **Case scaffold**
  ```bash
  new-case customer-acme-credential-stuffing
  # -> ~/Cases/CASE-YYYYmmdd-customer-acme-credential-stuffing/
  ```

- **OSINT feeds to SQLite**
  ```bash
  ti-feeds        # pulls CISA, NVD, Krebs, BleepingComputer, PD blog, Tor blog
  sqlite3 ~/OSINT/feeds.db ".tables"  # inspect
  ```

- **Handy aliases**
  ```bash
  sf          # spiderfoot -l 127.0.0.1:5001
  recon       # recon-ng
  th          # theHarvester
  pc          # proxychains4
  qr          # alias for quick-recon -d
  ```

---

## ✅ Verification

```bash
ti-health
subfinder -version && httpx -version && nuclei -version
proxychains4 -q curl -s https://api.ipify.org && torsocks curl -s https://api.ipify.org
spiderfoot -h && recon-ng -h && theHarvester -h
```

---

## 🔒 Security Notes

- Default firewall: `deny incoming / allow outgoing` (can be skipped via `--no-ufw`).
- ProxyChains configured with **dynamic_chain** + **proxy_dns** and **Tor** at `127.0.0.1:9050`.
- Offensive tools require **explicit** `--with-offsec`.
- History is persisted (append on each command) to improve auditing.

---

## 🧭 Usage Examples

**Passive recon (safe):**
```bash
quick-recon -d example.com
```

**Via Tor (dark-web or cautious egress):**
```bash
quick-recon -d example.com --proxy tor
```

**Dark-web crawl (know your scope):**
```bash
torbot -u http://exampleonion.onion
```

**theHarvester basic:**
```bash
theHarvester -d example.com -b bing
```

**nuclei targeted severity (safe baseline already used by quick-recon):**
```bash
nuclei -l hosts_httpx.txt -severity low,medium
```

---

## 🧩 Tooling Matrix (by Area)

- **TI/OSINT:** SpiderFoot, theHarvester, Recon-ng, Sublist3r, Amass, dnstwist, sn0int  
- **EASM:** subfinder, httpx, naabu, nuclei, katana, Nmap, Masscan, Seclists  
- **Dark-web:** Tor, Torsocks, ProxyChains, OnionShare, Tor Browser, TorBot  
- **Metadata/Evidence:** ExifTool, Metagoofil, Chromium (headless screenshots)  
- **DFIR (light):** Yara, binwalk, foremost, (optional `volatility3`)  
- **Offensive (opt-in):** Hashcat, John, Hydra, CUPP

---

## 🐞 Troubleshooting

- **`proxychains4` says config not found**  
  Kali sometimes ships `proxychains4.conf`. Installer auto-detects; re-run if needed.

- **Tor inactive in `ti-health`**  
  Start manually: `sudo systemctl start tor`; then `sudo systemctl enable tor`.

- **Chromium missing for `webshot`**  
  Reinstall: `sudo apt-get install -y chromium`.

- **nuclei templates empty**  
  Run: `nuclei -update -ut` or `sudo ti-update`.

---

## 🤝 Contributing

PRs and issues are welcome. Ideas that are especially helpful:
- New **presets** for specific TI/CSOC workflows
- Additional **RSS feeds** for `ti-feeds`
- Safe **automation** improvements or reporting formats

---

## ⚖️ Disclaimer

This project is for **legal and ethical** cybersecurity research, blue-team ops, and training. You are responsible for complying with all applicable laws and for obtaining proper authorization.

---

## 📜 License

This project is licensed. See [`LICENSE`](LICENSE) for details.

---

### Appendix: Legacy Script Note

If your workflow still references `kalitelligence.sh`, it will continue to work. New features and documentation, however, target **`kali-ti-suite.sh`**. Rename your pipeline scripts accordingly for consistency.
