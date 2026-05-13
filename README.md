````markdown
<div align="center">

<br/>

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ██████╗ ██╗   ██╗████████╗███████╗███████╗ ██████╗ █████╗   ║
║     ██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗  ║
║     ██████╔╝██║   ██║   ██║   █████╗  ███████╗██║     ███████║  ║
║     ██╔══██╗██║   ██║   ██║   ██╔══╝  ╚════██║██║     ██╔══██║  ║
║     ██████╔╝╚██████╔╝   ██║   ███████╗███████║╚██████╗██║  ██║  ║
║     ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝  ║
║                                                                   ║
║        Advanced Network Scanner - Fast, Powerful, Reliable       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

### ⚡ Lightning-Fast Network Scanning with Nmap-Style Power

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-blue?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-Yes-96c40f?style=for-the-badge)

**[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Support](#-support)**

</div>

---

## 📋 Overview

**Butescan** is a high-performance network scanner written in Go that combines the raw speed of RustScan with the sophisticated detection capabilities of Nmap. Designed for security researchers, penetration testers, and network administrators who need comprehensive port scanning with advanced enumeration.

```bash
# Fast subnet scan
sudo ./butescan -t 192.168.0.0/24 -A --cve --format html --output report.html

# Stealth reconnaissance
sudo ./butescan -t target.com -sS -p 1-65535 -O -sV --script ssh-hostkey,http-headers

# Quick vulnerability audit
sudo ./butescan -t internal-db.local -p 3306,5432,6379,27017 --cve -O
```

---

## ⭐ Features

| Feature | Description | Capability |
|---------|-------------|-----------|
| 🚀 **Fast Port Scanning** | 1000s of concurrent connections | Up to 65,535 ports |
| 🔍 **Service Detection** | Automatic service identification | 30+ services recognized |
| 🏷️ **Version Detection** | Extract service versions | From banner analysis |
| 🛡️ **CVE Lookup** | Real-time vulnerability search | NVD API integration |
| 📜 **NSE Scripts** | Built-in enumeration scripts | 20+ powerful scripts |
| 🖥️ **OS Detection** | Passive fingerprinting | TTL, banners, port signatures |
| 🌐 **CIDR Support** | Subnet scanning | 192.168.0.0/24 format |
| 📊 **Multi-Format Reports** | Generate scan reports | Text, JSON, HTML |
| 🔊 **UDP Scanning** | UDP service enumeration | DNS, SNMP, NTP, etc. |
| 🎯 **Nmap-Style Scans** | Multiple scan techniques | SYN, TCP, UDP, ACK, Window |

---

## 🚀 Quick Installation

### Prerequisites
- **Go 1.21+** → [Download](https://go.dev/dl/)
- **Linux/macOS** (Windows support via WSL2)
- **Root access** (for SYN scans)

### Build from Source

```bash
# Clone repository
git clone https://github.com/byte-err404/butescan.git
cd butescan

# Build binary
chmod +x build.sh
./build.sh

# Verify installation
./butescan -h
```

### Quick Start

```bash
# 1. Basic scan
sudo ./butescan -t 192.168.1.1

# 2. Aggressive scan with all features
sudo ./butescan -t 192.168.1.1 -A

# 3. View available scripts
./butescan --help-scripts

# 4. Full port scan with CVE lookup
sudo ./butescan -t 192.168.1.1 -p 1-65535 --cve -O --format html -o scan.html
```

---

## 📖 Scan Types Reference

### TCP Scans

| Scan Type | Flag | Description | Use Case |
|-----------|------|-------------|----------|
| **SYN Scan** | `-sS` | Half-open scan (stealth) | Default reconnaissance |
| **Connect Scan** | `-sT` | Full TCP connection | No root required |
| **ACK Scan** | `-sA` | Firewall rule mapping | Firewall detection |
| **Window Scan** | `-sW` | TCP window analysis | OS fingerprinting |
| **Maimon Scan** | `-sM` | FIN+ACK probe | Legacy systems |
| **Idle Scan** | `-sI` | Zombie host scan | Maximum stealth |

### Other Scans

| Scan Type | Flag | Description | Use Case |
|-----------|------|-------------|----------|
| **UDP Scan** | `-sU` | UDP service enumeration | DNS, SNMP, NTP |
| **IP Protocol Scan** | `-sO` | Protocol detection | GRE, IGMP, ICMP |
| **Skip Ping** | `-Pn` | Skip host discovery | Treat all as alive |

---

## 🛠️ Common Commands

### Basic Scanning
```bash
# Single host
sudo ./butescan -t 192.168.1.1

# Specific ports
sudo ./butescan -t 192.168.1.1 -p 80,443,22

# Port range
sudo ./butescan -t 192.168.1.1 -p 1-10000

# Top common ports
sudo ./butescan -t 192.168.1.1 --top-ports 1000
```

### Advanced Scanning
```bash
# SYN Stealth Scan
sudo ./butescan -t 192.168.1.1 -sS -p 1-65535

# Service version detection
sudo ./butescan -t 192.168.1.1 -sV

# OS fingerprinting
sudo ./butescan -t 192.168.1.1 -O

# Aggressive (everything)
sudo ./butescan -t 192.168.1.1 -A
```

### Enumeration & Scripts
```bash
# Run specific scripts
sudo ./butescan -t 192.168.1.1 -p 80,443 --script http-headers,ssl-cert

# All HTTP scripts
sudo ./butescan -t 192.168.1.1 -p 80,443 \
  --script http-headers,http-title,http-methods,http-robots,ssl-cert,ssl-heartbleed

# Database enumeration
sudo ./butescan -t 192.168.1.1 -p 3306,5432,6379,27017 \
  --script mysql-info,redis-info,mongodb-info
```

### Reporting & Output
```bash
# JSON report
sudo ./butescan -t 192.168.1.1 --format json -o scan.json

# HTML report
sudo ./butescan -t 192.168.1.1 --format html -o report.html

# Verbose output
sudo ./butescan -t 192.168.1.1 -v
```

### Performance Tuning
```bash
# Increase threads (faster)
sudo ./butescan -t 192.168.1.1 -c 5000

# Reduce timeout (faster but less reliable)
sudo ./butescan -t 192.168.1.1 -T 500

# Rate limiting (gentle scanning)
sudo ./butescan -t 192.168.1.1 --rate-limit 100
```

### Subnet & CIDR Scanning
```bash
# Scan entire subnet
sudo ./butescan -t 192.168.0.0/24 --top-ports 100

# Larger CIDR block
sudo ./butescan -t 10.0.0.0/16 -p 22,80,443 -O

# CIDR with aggressive scan
sudo ./butescan -t 192.168.0.0/24 -A --cve --format html -o subnet-audit.html
```

---

## 📜 NSE-Style Scripts (20+ Built-in)

### HTTP/HTTPS Scripts
```bash
http-headers       # HTTP security headers
http-title         # Web page title extraction
http-methods       # Dangerous HTTP methods (PUT, DELETE)
http-robots        # robots.txt enumeration
ssl-cert           # SSL/TLS certificate info
ssl-heartbleed     # Heartbleed vulnerability check
```

### SSH Scripts
```bash
ssh-hostkey        # SSH host key enumeration
ssh-auth-methods   # SSH auth method detection
```

### FTP/SMTP Scripts
```bash
ftp-anon           # Anonymous FTP login test
smtp-commands      # SMTP capabilities
smtp-open-relay    # Open mail relay detection
```

### Database Scripts
```bash
mysql-info         # MySQL version detection
redis-info         # Redis service enumeration
redis-unauth       # Unauthenticated Redis access
mongodb-info       # MongoDB enumeration
```

### Network Scripts
```bash
dns-brute          # DNS subdomain enumeration
snmp-info          # SNMP community string check
vnc-info           # VNC service detection
telnet-ntlm-info   # Telnet service detection
```

---

## 📊 Real-World Examples

### Web Server Security Audit
```bash
sudo ./butescan -t example.com -p 80,443 -A \
  --script http-headers,http-methods,http-robots,ssl-cert,ssl-heartbleed \
  --cve --format html --output web-audit.html
```

### Database Server Enumeration
```bash
sudo ./butescan -t db.internal -p 3306,5432,6379,27017 -sV \
  --script mysql-info,redis-info,mongodb-info \
  --cve --format json --output db-enum.json
```

### Network-Wide Reconnaissance
```bash
sudo ./butescan -t 10.0.0.0/16 --top-ports 20 -Pn -O \
  --script http-headers,ssh-hostkey,ftp-anon \
  --format html --output network-recon.html
```

### Firewall Rule Mapping
```bash
sudo ./butescan -t 192.168.1.1 -p 1-10000 -sA -sW \
  --format json --output firewall-map.json
```

### Comprehensive Security Audit
```bash
sudo ./butescan -t 192.168.0.0/24 \
  -p 1-10000 -A \
  --script http-headers,ssh-hostkey,ftp-anon,smtp-commands,mysql-info,redis-unauth \
  --cve -v \
  --format html --output comprehensive-audit.html
```

---

## 🔧 Complete Flag Reference

```bash
USAGE: butescan -t <target> [flags]

TARGET OPTIONS:
  -t, --target string         Target host/IP/CIDR (required)
  -p, --ports string          Port range: 80,443 or 1-65535
      --top-ports int         Scan top N common ports

SCAN TECHNIQUES:
  -sS                         TCP SYN scan (stealth, requires root)
  -sT                         TCP Connect scan
  -sU                         UDP scan
  -sA                         TCP ACK scan (firewall detection)
  -sW                         TCP Window scan
  -sM                         TCP Maimon scan
  -sI                         Idle/Zombie scan
  -sO                         IP protocol scan
  -Pn                         Skip host discovery

DETECTION OPTIONS:
  -sV, --version              Service version detection
  -O, --os                    OS fingerprinting
  -A, --aggressive            Aggressive (OS + version + scripts)
      --banner                Enable banner grabbing

ENUMERATION:
      --cve                   CVE vulnerability lookup
      --script strings        NSE-style scripts (comma-separated)

PERFORMANCE:
  -c, --threads int           Concurrent threads (default: 1000)
  -T, --timeout int           Timeout in milliseconds (default: 1000)
      --rate-limit int        Rate limit between requests (ms)

OUTPUT:
  -o, --output string         Output file path
      --format string         Format: text, json, html (default: text)

MISC:
  -v, --verbose               Verbose output
  -h, --help                  Show help menu
      --help-scripts          Show available scripts
```

---

## 📈 Performance Tips

| Scenario | Recommendation | Command |
|----------|----------------|---------|
| **Fast Scan** | Increase threads, reduce timeout | `-c 5000 -T 500` |
| **Stealthy Scan** | Reduce threads, increase rate limit | `-c 100 --rate-limit 200` |
| **Reliable Scan** | Increase timeout, moderate threads | `-c 2000 -T 2000` |
| **Large Subnet** | Use top ports, limited threads | `--top-ports 100 -c 1000` |

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| **"Permission denied" for SYN scan** | Use `sudo` for `-sS` flag |
| **Slow UDP scanning** | Use `--top-ports` or reduce port range |
| **CVE lookup rate limited** | Set `NVD_API_KEY` environment variable |
| **High false positives** | Increase timeout with `-T` flag |
| **Timeout errors** | Reduce threads with `-c` or increase timeout |

---

## 📜 CVE Lookup

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

```bash
# Basic CVE lookup
sudo ./butescan -t 192.168.1.1 --cve

# With API key (higher rate limits)
export NVD_API_KEY=your-api-key
sudo ./butescan -t 192.168.1.1 --cve
```

---

## 💡 Best Practices

- ✅ Always get **written permission** before scanning
- ✅ Use `-Pn` for hosts that don't respond to ping
- ✅ Start with `--top-ports` for initial reconnaissance
- ✅ Use `-c 100-500` for network-wide scans to avoid overwhelming targets
- ✅ Set NVD_API_KEY for better CVE lookup performance
- ✅ Generate HTML reports with `--format html` for better visualization
- ✅ Use `-T 2000` for unreliable/slow networks

---

## ⚠️ Legal & Ethical Notice

```
⚠️  IMPORTANT: Unauthorized access to computer systems is illegal.

• Only scan systems you own or have EXPLICIT written permission to scan
• Understand your local laws regarding network scanning and penetration testing
• Port scanning without authorization may violate:
  - Computer Fraud and Abuse Act (CFAA) in the USA
  - Computer Misuse Act in the UK
  - Similar laws in other jurisdictions

This tool is designed for defensive security professionals and authorized testing.
Always obtain written permission before testing any system you do not own.
```

---

## 📞 Support & Contact

<div align="center">

### 🤝 Need Help?

| Channel | Link | Response Time |
|---------|------|----------------|
| 📧 **Email** | [support@butescan.dev](mailto:support@butescan.dev) | 24-48 hours |
| 🐛 **Issues** | [GitHub Issues](https://github.com/byte-err404/butescan/issues) | 24-72 hours |
| 💬 **Discussions** | [GitHub Discussions](https://github.com/byte-err404/butescan/discussions) | 24-48 hours |
| 🔗 **Twitter** | [@butescan_dev](https://twitter.com/butescan_dev) | Real-time |
| 📚 **Wiki** | [Project Wiki](https://github.com/byte-err404/butescan/wiki) | Always updated |

### 🚀 Quick Links

- 📖 [Full Documentation](https://github.com/byte-err404/butescan/wiki)
- 🐛 [Report a Bug](https://github.com/byte-err404/butescan/issues/new?labels=bug)
- 💡 [Feature Request](https://github.com/byte-err404/butescan/issues/new?labels=enhancement)
- 📝 [Contributing Guide](./CONTRIBUTING.md)

### 👥 Community

- **Contributors**: [GitHub Contributors](https://github.com/byte-err404/butescan/graphs/contributors)
- **Stars**: ⭐ Star us on GitHub if you find this useful!
- **Share**: [Share your feedback](https://twitter.com/intent/tweet?text=Check%20out%20%40butescan_dev%20-%20Advanced%20Network%20Scanner)

</div>

---

## 📋 Supported Services & Protocols

**30+ Services Recognized:**

SSH • HTTP/HTTPS • FTP • SMTP/POP3/IMAP • DNS • SNMP • NTP • NFS • SMTP • MySQL • PostgreSQL • MongoDB • Redis • Elasticsearch • Memcached • RabbitMQ • CouchDB • Apache • Nginx • IIS • Tomcat • Jenkins • Docker • Kubernetes • Cassandra • Kibana • Grafana • Prometheus • Jaeger • and more...

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](./LICENSE) file for details.

```
MIT License - Free for personal and commercial use
```

---

## 🙏 Acknowledgments

- Inspired by **Nmap**, **RustScan**, and **Masscan**
- Built with Go's powerful networking libraries
- NVD API integration for vulnerability data
- Thanks to the security research community

---

<div align="center">

**Made with ❤️ by [byte-err404](https://github.com/byte-err404)**

*Last Updated: 2026-05-13 | Version: 1.0.0*

[⬆ Back to Top](#-butescan--advanced-network-scanner)

</div>

````
