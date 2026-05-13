````markdown
# ⚡ Butescan — Advanced Network Scanner

![Go](https://img.shields.io/badge/Go-1.21-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)

A fast, feature-rich network scanner written in Go — combining the speed of RustScan with Nmap-inspired detection and enumeration.

---

# Features

| Feature | Description |
|---|---|
| 🚀 Fast Port Scan | Concurrent scanning with configurable thread pool (like rustscan) |
| 🔍 Service Detection | Auto-detects 30+ services from banners |
| 🏷️ Version Detection | Extracts service versions from banners |
| 🛡️ CVE Lookup | Real-time CVE search via NVD API |
| 📜 Script Engine | 20+ built-in NSE-style scripts |
| 🖥️ OS Detection | Passive fingerprinting using TTL, banners, and port signatures |
| 🌐 CIDR Support | Scan entire subnets (e.g. 192.168.1.0/24) |
| 📊 Reports | JSON, HTML, and text output |
| 🔊 UDP Scanning | DNS, SNMP, NTP and more |
| 🎯 Nmap-Style Scans | SYN, TCP, UDP, ACK, Window, Maimon, Idle, IP Protocol scans |

---

# Detection Engine

Butescan combines multiple fingerprinting techniques:

- TCP banner analysis
- TLS handshake parsing
- HTTP fingerprinting
- TTL-based OS detection
- Port signature matching
- Protocol-aware service detection

Detection confidence levels:

- High
- Medium
- Low

---

# Supported Services

SSH, HTTP, HTTPS, FTP, SMTP, Redis, MongoDB, MySQL, PostgreSQL, DNS, SNMP, VNC, Telnet, RDP, SMB, LDAP, MQTT, NTP and more.

---

# Installation

## Prerequisites

Go 1.21+ → https://go.dev/dl/

```bash
git clone https://github.com/byte-err404/butescan
cd butescan
chmod +x build.sh
./build.sh
```

---

# Usage

## Quick Start

### Basic Scan
```bash
sudo ./butescan -t 192.168.1.1
```

### Full Port Scan with Service Detection
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 --banner
```

### Scan a Subnet
```bash
sudo ./butescan -t 192.168.1.0/24 --top-ports 100
```

### CVE Vulnerability Check
```bash
sudo ./butescan -t 10.0.0.5 -p 1-1000 --cve
```

### OS Detection
```bash
sudo ./butescan -t 192.168.1.1 -O
```

### Run Specific Scripts
```bash
sudo ./butescan -t 192.168.1.1 -p 80,443 --script http-headers,ssl-cert
```

### Full Security Audit
```bash
sudo ./butescan -t 10.0.0.0/24 \
  -p 1-10000 \
  --cve \
  -O \
  --banner \
  --script http-headers,ssl-cert,redis-unauth,ftp-anon,ssh-hostkey \
  --format html \
  --output report.html
```

### Save JSON Report
```bash
sudo ./butescan -t 192.168.1.1 --format json --output scan.json
```

### Fast Scan (High Thread Count)
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 -c 5000 -T 500
```

---

# Nmap-Style Scan Types

Butescan supports multiple scanning techniques similar to Nmap:

## TCP Scans

### SYN Scan (Stealth Scan)
```bash
sudo ./butescan -t 192.168.1.1 -sS
```
- **Description**: Half-open scan, doesn't complete TCP connection
- **Pros**: Fast, stealthy, doesn't log connection completion
- **Cons**: Requires root/admin privileges
- **Use Case**: Stealth reconnaissance on networks you own

### TCP Connect Scan
```bash
sudo ./butescan -t 192.168.1.1 -sT
```
- **Description**: Full TCP connection scan using OS connection API
- **Pros**: Works without root, doesn't leave logs at application level
- **Cons**: Slower than SYN scan, detected in connection logs
- **Use Case**: Default scanning method, works from user space

### ACK Scan (Firewall Detection)
```bash
sudo ./butescan -t 192.168.1.1 -sA
```
- **Description**: Sends ACK packets to probe firewall rules
- **Pros**: Maps firewall rules, detects stateful firewalls
- **Cons**: Doesn't determine if port is open, only filtered/unfiltered
- **Use Case**: Firewall rule mapping and detection

### Window Scan (OS Fingerprinting)
```bash
sudo ./butescan -t 192.168.1.1 -sW
```
- **Description**: Examines TCP window field for OS fingerprinting
- **Pros**: Can fingerprint OS, similar to ACK scan
- **Cons**: Unreliable on modern systems
- **Use Case**: Advanced OS detection

### Maimon Scan
```bash
sudo ./butescan -t 192.168.1.1 -sM
```
- **Description**: FIN+ACK probe for BSD systems
- **Pros**: Rare, might evade some detection
- **Cons**: Mostly obsolete on modern systems
- **Use Case**: Legacy system scanning

### Idle/Zombie Scan
```bash
sudo ./butescan -t 192.168.1.1 -sI <zombie-host>
```
- **Description**: Uses a third "zombie" host to perform scan
- **Pros**: Highly stealthy, hard to trace to attacker
- **Cons**: Very slow, requires finding idle host with predictable IP IDs
- **Use Case**: Maximum stealth scanning (educational use)

## UDP Scan
```bash
sudo ./butescan -t 192.168.1.1 -sU -p 53,161
```
- **Description**: Sends UDP packets to detect UDP services
- **Pros**: Detects DNS, SNMP, NTP, and other UDP services
- **Cons**: Much slower than TCP, high packet loss
- **Use Case**: Complete service enumeration

## IP Protocol Scan
```bash
sudo ./butescan -t 192.168.1.1 -sO
```
- **Description**: Determines which IP protocols are supported
- **Pros**: Detects GRE, IGMP, ICMP, and other protocols
- **Cons**: Rarely used in practice
- **Use Case**: Protocol enumeration

---

# Detection Flags

### Service Version Detection
```bash
sudo ./butescan -t 192.168.1.1 -sV
```
Enables automatic service version detection from banners

### OS Detection
```bash
sudo ./butescan -t 192.168.1.1 -O
```
Performs passive OS fingerprinting using TTL analysis and port signatures

### Aggressive Scan
```bash
sudo ./butescan -t 192.168.1.1 -A
```
Enables everything: OS detection, version detection, banner grabbing, and common scripts

### Skip Host Discovery (Ping)
```bash
sudo ./butescan -t 192.168.1.1 -Pn
```
Treats all hosts as online, skips ICMP ping check

---

# Performance Options

### Connection Timeout
```bash
sudo ./butescan -t 192.168.1.1 -T 500
```
Set connection timeout in milliseconds (default: 1000ms)

### Thread Count
```bash
sudo ./butescan -t 192.168.1.1 -c 5000
```
Number of concurrent threads (default: 1000, max recommended: 5000)

### Rate Limiting
```bash
sudo ./butescan -t 192.168.1.1 --rate-limit 100
```
Milliseconds between requests to avoid overwhelming targets

---

# Output Formats

### Text Output (Default)
```bash
sudo ./butescan -t 192.168.1.1 --format text
```

### JSON Output
```bash
sudo ./butescan -t 192.168.1.1 --format json --output scan.json
```

### HTML Report
```bash
sudo ./butescan -t 192.168.1.1 --format html --output report.html
```

---

# All Flags Reference

```bash
Usage:
  butescan -t <target> [flags]

TARGET OPTIONS:
  -t, --target string    Target host/IP/CIDR range (required)
  -p, --ports string     Port range (e.g., 80,443 or 1-65535, default: 1-1024)
      --top-ports int    Scan top N common ports (e.g., 100, 1000)

SCAN TECHNIQUES:
  -sS                    TCP SYN scan (stealth, requires root)
  -sT                    TCP Connect scan (full connection)
  -sU                    UDP scan
  -sA                    TCP ACK scan (firewall detection)
  -sW                    TCP Window scan (OS fingerprinting)
  -sM                    TCP Maimon scan
  -sI                    Idle/Zombie scan (advanced, slow)
  -sO                    IP protocol scan

DETECTION OPTIONS:
  -sV, --version         Service/version detection
  -O, --os               OS detection (passive fingerprinting)
  -A, --aggressive       Aggressive scan (OS + version + scripts)
      --banner           Enable banner grabbing
      -Pn                Treat all hosts as online (skip ping)

ENUMERATION:
      --cve              CVE lookup for detected services
      --script strings   Comma-separated NSE-style scripts to run

PERFORMANCE:
  -c, --threads int      Concurrent threads (default: 1000)
  -T, --timeout int      Timeout in milliseconds (default: 1000)
      --rate-limit int   Rate limit between requests (ms)

OUTPUT:
  -o, --output string    Output file path
      --format string    Output format: text, json, html (default: text)

MISC:
  -v, --verbose          Verbose output
  -h, --help             Show this help menu
      --help-scripts     Show available NSE-style scripts
```

---

# Built-in NSE-Style Scripts

Run `./butescan --help-scripts` to see all available scripts.

## HTTP/HTTPS Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `http-headers` | Dump all HTTP response headers | 80,443,8080,8443 | Security headers check, server identification |
| `http-title` | Extract page title | 80,443,8080,8443 | Service identification |
| `http-methods` | Find dangerous HTTP methods | 80,443,8080,8443 | Detect PUT, DELETE, TRACE, CONNECT methods |
| `http-robots` | Read robots.txt | 80,443,8080,8443 | Find hidden paths and directories |
| `ssl-cert` | TLS certificate info + expiry check | 443,8443 | Certificate validation and expiry check |
| `ssl-heartbleed` | Check for CVE-2014-0160 (Heartbleed) | 443,8443 | Detect OpenSSL Heartbleed vulnerability |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 80,443 --script http-headers,http-title,ssl-cert
```

---

## SSH Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `ssh-hostkey` | SSH banner, host keys, and key types | 22 | SSH service identification and key collection |
| `ssh-auth-methods` | Enumerate SSH authentication methods | 22 | Find supported auth methods (password, key, gssapi) |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 22 --script ssh-hostkey,ssh-auth-methods
```

---

## FTP Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `ftp-anon` | Test anonymous FTP login | 21 | Check for anonymous access |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 21 --script ftp-anon
```

---

## SMTP Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `smtp-commands` | Enumerate SMTP EHLO commands | 25,587 | Identify SMTP capabilities |
| `smtp-open-relay` | Test for open mail relay | 25 | Detect email relay vulnerabilities |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 25,587 --script smtp-commands,smtp-open-relay
```

---

## Database Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `mysql-info` | MySQL version from handshake | 3306 | MySQL version detection |
| `redis-info` | Redis INFO (unauthenticated) | 6379 | Check unauthenticated Redis access |
| `redis-unauth` | Test unauthenticated Redis access | 6379 | Verify Redis authentication required |
| `mongodb-info` | MongoDB version/access check | 27017 | MongoDB service enumeration |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 3306,6379,27017 --script mysql-info,redis-info,mongodb-info
```

---

## Network/DNS Scripts

| Script | Description | Port | Use Case |
|---|---|---|---|
| `dns-brute` | DNS subdomain brute-force | 53 | Subdomain enumeration |
| `snmp-info` | SNMP public community string check | 161 | Detect SNMP with public community |
| `vnc-info` | VNC version and auth type | 5900 | VNC service identification |
| `telnet-ntlm-info` | Telnet banner (protocol insecurity) | 23 | Telnet service detection |

### Example:
```bash
sudo ./butescan -t 192.168.1.1 -p 53,161,5900,23 --script dns-brute,snmp-info,vnc-info,telnet-ntlm-info
```

---

# Script Usage Examples

### Run Multiple Scripts
```bash
sudo ./butescan -t 192.168.1.1 -p 80,443,22,3306 \
  --script http-headers,http-title,ssl-cert,ssh-hostkey,mysql-info
```

### Run All HTTP Scripts
```bash
sudo ./butescan -t 192.168.1.1 -p 80,443 \
  --script http-headers,http-title,http-methods,http-robots,ssl-cert,ssl-heartbleed
```

### Security Audit on Standard Ports
```bash
sudo ./butescan -t 192.168.1.1 -p 21,22,25,53,80,110,143,443,3306,6379 \
  --script ftp-anon,ssh-hostkey,smtp-commands,dns-brute,http-headers,ssl-cert,mysql-info,redis-info \
  --cve -O -sV
```

### Comprehensive Network Scan
```bash
sudo ./butescan -t 192.168.1.0/24 \
  -p 1-10000 \
  -A \
  --script http-headers,ssh-hostkey,ftp-anon,smtp-commands,mysql-info,redis-info,mongodb-info,ssl-cert \
  --cve \
  --format html \
  --output network-audit.html
```

---

# CVE Lookup

Uses the NVD (National Vulnerability Database) REST API v2.0.

## Basic CVE Lookup
```bash
./butescan -t 192.168.1.1 --cve
```

## With API Key (Higher Rate Limits)
```bash
export NVD_API_KEY=your-key-here
./butescan -t 192.168.1.1 --cve
```

Get a free NVD API key at:
https://nvd.nist.gov/developers/request-an-api-key

---

# Advanced Examples

## Full Security Audit
```bash
sudo ./butescan -t 10.0.0.0/24 \
  -p 1-10000 \
  -A \
  --script http-headers,http-title,http-methods,ssl-cert,ssh-hostkey,ftp-anon,smtp-commands,mysql-info,redis-unauth,mongodb-info \
  --cve \
  -v \
  --format html \
  --output audit.html
```

## Stealth Scan
```bash
sudo ./butescan -t 192.168.1.1 -sS -p 1-65535 -c 100 -T 2000
```

## Quick Port Check
```bash
sudo ./butescan -t 192.168.1.1 --top-ports 100
```

## Subnet Discovery
```bash
sudo ./butescan -t 192.168.0.0/24 -p 22,80,443 -O -sV
```

## Intense Scan
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 -A --cve -c 5000 -T 500
```

---

# Example Output

```text
  ██████╗ ██╗   ██╗████████╗███████╗
  ██╔══██╗██║   ██║╚══██╔══╝██╔════╝
  ██████╔╝██║   ██║   ██║   █████╗
  ██╔══██╗██║   ██║   ██║   ██╔══╝
  ██████╔╝╚██████╔╝   ██║   ███████╗
  ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

[*] Scan Type: TCP SYN (stealth)
[*] Service Detection: Enabled
[*] OS Detection: Enabled
[*] CVE Lookup: Enabled
[*] Targets: 1 | Ports: 1000 | Threads: 1000 | Timeout: 1000ms
[>] Scanning 192.168.1.1 ...
[+] OS Detected: Linux (Ubuntu)
[!] Port 6379/tcp: 3 CVE(s) found

╔══════════════════════════════════════════════════╗
║  Host: 192.168.1.1                              ║
║  OS:   Linux (Ubuntu)                           ║
╚══════════════════════════════════════════════════╝

  PORT     STATE    SERVICE              VERSION            BANNER
─────────────────────────────────────────────────────────────────────
  22/tcp   open     ssh                  OpenSSH 8.9        SSH-2.0-OpenSSH_8.9p1
  80/tcp   open     http                 Apache 2.4.52      HTTP/1.1 200 OK
  443/tcp  open     https                nginx 1.22         HTTP/1.1 200 OK
  6379/tcp open     redis                                    +PONG [3 CVEs]

[✓] Scan completed in 45.234s
[✓] Report saved to: scan-report.html
```

---

# Common Scanning Scenarios

## Web Server Security Audit
```bash
sudo ./butescan -t webserver.com -p 80,443 -A \
  --script http-headers,http-methods,http-robots,ssl-cert,ssl-heartbleed \
  --cve --format html --output web-audit.html
```

## Database Server Scan
```bash
sudo ./butescan -t db.internal -p 3306,5432,6379,27017 -sV \
  --script mysql-info,redis-info,mongodb-info \
  --cve --format json --output db-scan.json
```

## Network-Wide Reconnaissance
```bash
sudo ./butescan -t 10.0.0.0/16 --top-ports 20 -Pn \
  --script http-headers,ssh-hostkey,ftp-anon \
  -O --format html --output network-recon.html
```

## Firewall Rule Testing
```bash
sudo ./butescan -t 192.168.1.1 -p 1-10000 -sA -sW \
  --format json --output firewall-map.json
```

---

# Troubleshooting

### Permission Denied (SYN Scan)
**Problem**: SYN scan requires root privileges
```bash
# Wrong:
./butescan -t 192.168.1.1 -sS

# Correct:
sudo ./butescan -t 192.168.1.1 -sS
```

### Slow UDP Scan
**Problem**: UDP scanning is inherently slow
**Solution**: Reduce port range or use `--top-ports`
```bash
# Faster:
sudo ./butescan -t 192.168.1.1 -sU --top-ports 50
```

### CVE Lookup Rate Limited
**Problem**: NVD API has rate limits without API key
**Solution**: Set NVD_API_KEY environment variable
```bash
export NVD_API_KEY=your-key-from-nvd.nist.gov
sudo ./butescan -t 192.168.1.1 --cve
```

### High False Positives
**Problem**: Timeout too short
**Solution**: Increase timeout
```bash
sudo ./butescan -t 192.168.1.1 -T 2000
```

---

# Notes

- SYN scan requires root privileges
- UDP scanning is significantly slower than TCP scanning
- CVE lookups may be rate-limited without an NVD API key
- Banner-based detection may not always identify exact versions
- ACK and Window scans cannot determine if ports are open (only filtered/unfiltered)
- Idle/Zombie scan is very slow and requires finding a suitable idle host

---

# Legal Notice

⚠️ **Only scan systems you own or have explicit permission to scan.**

Unauthorized port scanning may be illegal in your jurisdiction. Always obtain written permission before scanning any system you do not own.

---

# License

MIT
````
