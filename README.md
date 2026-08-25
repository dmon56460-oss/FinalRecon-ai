# 🕵️ FinalRecon-AI - Advanced Web Server Reconnaissance & Security Scanner

[![Version](https://img.shields.io/badge/version-2026.0-red.svg)](https://github.com/dmon56460-oss/FinalRecon-ai)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Advanced Web Server Reconnaissance & Security Scanner with Firewall/Web Server Destruction Capabilities**

---

## ⚠️ IMPORTANT DISCLAIMER

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY!**

- ❌ **DO NOT** use against any system without explicit written permission
- ❌ **DO NOT** use for illegal or malicious purposes
- ✅ **ONLY** use on systems you own or have permission to test
- ⚖️ The user assumes all responsibility for any misuse

---

## 📌 Features

### Reconnaissance Modules
- 🌐 **HTTP Header Enumeration** - Extract server headers and technologies
- 🔒 **SSL Certificate Analysis** - Analyze SSL/TLS certificates
- 📋 **WHOIS Lookup** - Domain registration information
- 🌍 **DNS Enumeration** - A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV records
- 🔍 **Subdomain Enumeration** - Find active subdomains
- 📂 **Directory Bruteforce** - Discover hidden directories
- 🔌 **Port Scanning** - Scan common and custom ports
- 🕰️ **Wayback Machine** - Historical URL discovery
- 🕷️ **Web Crawler** - Spider and crawl target website
- ⚠️ **Vulnerability Scanning** - Detect common security issues

### Advanced Security Features
- 🔥 **Firewall Detection & Destruction** - Detect and destroy WAFs
- 🌐 **Web Server Detection & Destruction** - Identify and destroy web servers
- 🔓 **Auto-Unlock** - Unlock locked devices
- 💀 **Suspicious System Destroy** - Destroy suspicious systems
- 🎯 **Custom Port Support** - Scan any port

---

## 🚀 Quick Installation

### Clone & Run

```bash
# Clone the repository
git clone https://github.com/dmon56460-oss/FinalRecon-ai.git

# Enter the project directory
cd FinalRecon-ai

# Install required dependencies
pip3 install -r requirements.txt

# Run a full scan
python3 finalrecon-ai.py --url https://example.com --full
