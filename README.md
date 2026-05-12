# ⚡ Butescan — Advanced Network Scanner

A fast, feature-rich network scanner written in Go — inspired by **nmap** and **rustscan**.

## Features

| Feature | Description |
|---|---|
| 🚀 Fast Port Scan | Concurrent scanning with configurable thread pool (like rustscan) |
| 🔍 Service Detection | Auto-detects 30+ services from banners |
| 🏷️ Version Detection | Extracts service version from banners |
| 🛡️ CVE Lookup | Real-time CVE search via NVD API |
| 📜 Script Engine | 20+ built-in NSE-style scripts |
| 🖥️ OS Detection | Fingerprinting via banners, TTL, port combos |
| 🌐 CIDR Support | Scan entire subnets (e.g. 192.168.1.0/24) |
| 📊 Reports | JSON, HTML, and text output |
| 🔊 UDP Scanning | DNS, SNMP, NTP and more |

## Installation

### Prerequisites
- Go 1.21+ → https://go.dev/dl/

```bash
git clone https://github.com/yourname/butescan
cd butescan
chmod +x build.sh
./build.sh
```

## Usage

```bash
# Basic scan (top 1000 ports)
sudo ./butescan -t 192.168.1.1

# Full port scan with service detection
sudo ./butescan -t 192.168.1.1 -p 1-65535 --banner

# Scan a subnet
sudo ./butescan -t 192.168.1.0/24 --top-ports 100

# CVE vulnerability check
sudo ./butescan -t 10.0.0.5 -p 1-1000 --cve

# OS detection
sudo ./butescan -t 192.168.1.1 --os

# Run specific scripts
sudo ./butescan -t 192.168.1.1 -p 80,443 --script http-headers,ssl-cert

# Full security audit
sudo ./butescan -t 10.0.0.0/24 \
  -p 1-10000 \
  --cve \
  --os \
  --banner \
  --script http-headers,ssl-cert,redis-unauth,ftp-anon,ssh-hostkey \
  --format html \
  --output report.html

# Save JSON report
sudo ./butescan -t 192.168.1.1 --format json --output scan.json

# Fast scan (high thread count)
sudo ./butescan -t 192.168.1.1 -p 1-65535 -c 5000 -T 500
```

## All Flags

```
-t, --target        Target host/IP/CIDR (required)
-p, --ports         Port range: 80,443 or 1-1024 or top (default: 1-1024)
    --top-ports     Scan top N common ports
-c, --threads       Concurrent threads (default: 1000)
-T, --timeout       Timeout in ms (default: 1000)
-s, --scan-type     tcp | syn | udp | all (default: tcp)
    --banner        Enable banner grabbing (default: true)
    --os            Enable OS detection
    --cve           Enable CVE lookup (NVD API)
    --script        Scripts to run (comma-separated)
-o, --output        Output file path
    --format        Output format: text | json | html
-v, --verbose       Verbose output
```

## Built-in Scripts

### HTTP/HTTPS
| Script | Description |
|---|---|
| `http-headers` | Dump all HTTP response headers |
| `http-title` | Extract page title |
| `http-methods` | Find dangerous HTTP methods (PUT, DELETE, TRACE) |
| `http-robots` | Read robots.txt for hidden paths |
| `ssl-cert` | TLS certificate info + expiry check |
| `ssl-heartbleed` | Check for CVE-2014-0160 (Heartbleed) |

### Services
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

## CVE Lookup

Uses the **NVD (National Vulnerability Database) REST API v2.0**.

```bash
# Basic CVE lookup (rate limited: 5 req/30s without API key)
./butescan -t 192.168.1.1 --cve

# With API key (higher rate limits)
# Set NVD_API_KEY environment variable:
export NVD_API_KEY=your-key-here
./butescan -t 192.168.1.1 --cve
```

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

## Example Output

```
  ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ...

[*] Starting GoScanner at 2025-01-15 14:30:00
[*] Targets: 1 host(s) | Ports: 1000 | Threads: 1000 | Timeout: 1000ms

[>] Scanning 192.168.1.1 ...
[+] OS Detected: Linux (Ubuntu)
[!] Port 6379/tcp (redis): 3 CVE(s) found!
    CVE-2022-0543        CVSS:10.0  Debian/Ubuntu Redis Lua sandbox escape
    CVE-2021-32761       CVSS:7.5   Redis integer overflow in GETDEL
    CVE-2021-29478       CVSS:7.5   Redis integer overflow on 32-bit systems

╔══════════════════════════════════════════════════╗
║  Host: 192.168.1.1                               ║
║  OS:   Linux (Ubuntu)                            ║
╚══════════════════════════════════════════════════╝
  PORT     STATE    SERVICE              VERSION            BANNER/CVE
────────────────────────────────────────────────────────────────────────────────
  22/tcp   open     ssh                  OpenSSH 8.9        SSH-2.0-OpenSSH_8.9p1
  80/tcp   open     http                 Apache 2.4.52      HTTP/1.1 200 OK
  443/tcp  open     https                nginx 1.22         HTTP/1.1 200 OK
  6379/tcp open     redis                                    +PONG [3 CVEs]
           └─ CVE-2022-0543 Lua sandbox escape... (CVSS: 10.0)
```

## Legal Notice

⚠️ **Only scan systems you own or have explicit permission to scan.**  
Unauthorized port scanning may be illegal in your jurisdiction.

## License
MIT
