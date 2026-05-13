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

## Basic Scan

```bash
sudo ./butescan -t 192.168.1.1
```

## Full Port Scan with Service Detection

```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 --banner
```

## Scan a Subnet

```bash
sudo ./butescan -t 192.168.1.0/24 --top-ports 100
```

## CVE Vulnerability Check

```bash
sudo ./butescan -t 10.0.0.5 -p 1-1000 --cve
```

## OS Detection

```bash
sudo ./butescan -t 192.168.1.1 --os
```

## Run Specific Scripts

```bash
sudo ./butescan -t 192.168.1.1 -p 80,443 --script http-headers,ssl-cert
```

## Full Security Audit

```bash
sudo ./butescan -t 10.0.0.0/24 \
  -p 1-10000 \
  --cve \
  --os \
  --banner \
  --script http-headers,ssl-cert,redis-unauth,ftp-anon,ssh-hostkey \
  --format html \
  --output report.html
```

## Save JSON Report

```bash
sudo ./butescan -t 192.168.1.1 --format json --output scan.json
```

## Fast Scan (High Thread Count)

```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 -c 5000 -T 500
```

---

# Advanced Examples

## SYN Scan

```bash
sudo ./butescan -t 192.168.1.1 -sS
```

## UDP Scan

```bash
sudo ./butescan -t 192.168.1.1 -sU -p 53,161
```

## Aggressive Scan

```bash
sudo ./butescan -t 192.168.1.1 -A
```

## Full Port Scan

```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535
```

---

# All Flags

```bash
Usage:
  butescan -t <target> [flags]

Scan Techniques:
  -sS                    TCP SYN scan
  -sT                    TCP connect scan
  -sU                    UDP scan

Detection:
  -sV, --version-detect  Enable service/version detection
  -O, --os               Enable OS fingerprinting
  -A, --aggressive       Enable OS detection, version detection and scripts

Host Discovery:
  -Pn                    Treat all hosts as online

Target Options:
  -t, --target string    Target host/IP/CIDR range (required)
  -p, --ports string     Port range (80,443 or 1-65535)
      --top-ports int    Scan top N common ports

Performance:
  -c, --threads int      Concurrent threads (default 1000)
  -T, --timeout int      Timeout in milliseconds (default 1000)

Enumeration:
      --banner           Enable banner grabbing
      --cve              Check CVEs for detected services
      --script strings   Comma-separated scripts to run

Output:
  -o, --output string    Output file path
      --format string    Output format: text, json, html

Misc:
  -v, --verbose          Verbose output
  -h, --help             Show help menu
```

---

# Built-in Scripts

## HTTP/HTTPS

| Script | Description |
|---|---|
| `http-headers` | Dump all HTTP response headers |
| `http-title` | Extract page title |
| `http-methods` | Find dangerous HTTP methods (PUT, DELETE, TRACE) |
| `http-robots` | Read robots.txt for hidden paths |
| `ssl-cert` | TLS certificate info + expiry check |
| `ssl-heartbleed` | Check for CVE-2014-0160 (Heartbleed) |

---

## Services

| Script | Description |
|---|---|
| `ssh-hostkey` | SSH banner and host key info |
| `ssh-auth-methods` | SSH authentication methods |
| `ftp-anon` | Test anonymous FTP login |
| `smtp-commands` | SMTP EHLO supported extensions |
| `smtp-open-relay` | Test for open mail relay |
| `mysql-info` | MySQL version from handshake |
| `redis-info` | Redis INFO (unauthenticated check) |
| `redis-unauth` | Test unauthenticated Redis access |
| `mongodb-info` | MongoDB version/access check |
| `vnc-info` | VNC version and auth type |
| `telnet-ntlm-info` | Telnet banner (insecure protocol check) |
| `snmp-info` | SNMP public community string check |
| `dns-brute` | DNS subdomain brute-force |

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

# Example Output

```text
  ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ...

[*] Starting Butescan at 2025-01-15 14:30:00
[*] Targets: 1 host(s) | Ports: 1000 | Threads: 1000 | Timeout: 1000ms

[>] Scanning 192.168.1.1 ...
[+] OS Detected: Linux (Ubuntu)

[!] Port 6379/tcp (redis): 3 CVE(s) found!
    CVE-2022-0543        CVSS:10.0  Debian/Ubuntu Redis Lua sandbox escape
    CVE-2021-32761       CVSS:7.5   Redis integer overflow in GETDEL
    CVE-2021-29478       CVSS:7.5   Redis integer overflow on 32-bit systems

╔══════════════════════════════════════════════════╗
║  Host: 192.168.1.1                              ║
║  OS:   Linux (Ubuntu)                           ║
╚══════════════════════════════════════════════════╝

  PORT     STATE    SERVICE              VERSION            BANNER/CVE
────────────────────────────────────────────────────────────────────────────────

  22/tcp   open     ssh                  OpenSSH 8.9        SSH-2.0-OpenSSH_8.9p1
  80/tcp   open     http                 Apache 2.4.52      HTTP/1.1 200 OK
  443/tcp  open     https                nginx 1.22         HTTP/1.1 200 OK
  6379/tcp open     redis                                    +PONG [3 CVEs]

           └─ CVE-2022-0543 Lua sandbox escape... (CVSS: 10.0)
```

---

# Notes

- SYN scan requires root privileges
- UDP scanning is significantly slower than TCP scanning
- CVE lookups may be rate-limited without an NVD API key
- Banner-based detection may not always identify exact versions

---

# Legal Notice

⚠️ Only scan systems you own or have explicit permission to scan.

Unauthorized port scanning may be illegal in your jurisdiction.

---

# License

MIT
