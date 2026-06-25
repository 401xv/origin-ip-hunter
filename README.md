# Origin IP Hunter 🚀
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Security](https://img.shields.io/badge/Security-Reconnaissance-red)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange)
![License](https://img.shields.io/badge/License-Educational-yellow)

Origin IP Hunter is an advanced reconnaissance and infrastructure intelligence tool built for bug bounty hunters, penetration testers, and security researchers. It helps identify potential origin servers and exposed infrastructure hidden behind CDNs, reverse proxies, and WAFs such as Cloudflare. 🛡️

Organizations commonly rely on CDN and security services to protect backend systems and conceal their real infrastructure. However, misconfigurations, historical records, passive intelligence sources, exposed services, certificate data, and forgotten assets can unintentionally reveal valuable information about the underlying environment.

Origin IP Hunter automates the collection, correlation, and verification of these indicators to streamline reconnaissance activities during authorized security assessments. ⚙️

---

## ✨ Features

* 🔍 DNS Record Analysis
* ⚠️ Configuration Leak Detection
* 📜 Historical DNS Intelligence
* 🔗 Passive DNS Correlation
* 📋 Certificate Transparency Enumeration
* 🌐 Subdomain Discovery
* 🎯 Direct Exposure Discovery
* 🖼️ Favicon Hash Correlation
* ✅ Candidate Origin Verification
* ☁️ Cloudflare Origin Hunting
* 📊 Automated Reporting

---

## 🏗️ Architecture

Origin IP Hunter follows a modular architecture, allowing researchers to execute individual reconnaissance modules or perform a full infrastructure assessment. The verification engine helps distinguish likely origin infrastructure from unrelated assets by correlating evidence from multiple independent sources. 🧠

---

## 🛠️ Installation & Usage

### 🐉 Method 1: Kali Linux / Debian

```bash
pip install requests dnspython mmh3 --break-system-packages

python3 origin_ip_hunter.py -d target.com -o report.txt
```

### 🧪 Method 2: Virtual Environment

```bash
# Create virtual environment
python3 -m venv ~/tools/origin-hunter

# Activate environment
source ~/tools/origin-hunter/bin/activate

# Install dependencies
pip install requests dnspython mmh3

# Run tool
python3 origin_ip_hunter.py -d target.com -o report.txt

# Exit environment
deactivate
```

### ⚡ Quick Run

```bash
source ~/tools/origin-hunter/bin/activate && \
python3 origin_ip_hunter.py -d target.com
```

---

## 📦 Requirements

```text
Python 3.10+
requests
dnspython
mmh3
```

---

## ⚖️ Disclaimer

This project is intended exclusively for educational purposes, authorized penetration testing, security research, and bug bounty programs. Users are responsible for ensuring compliance with all applicable laws, regulations, and program policies.

---

## 👨‍💻 Author

**Reza**

🐍 Language: Python

🔐 Category: Security Automation • Reconnaissance • Bug Bounty
