```
██████╗ ██╗   ██╗████████╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║   ██║   █████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔══██╗██║   ██║   ██║   ██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝╚██████╔╝   ██║   ███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

<div align="center">

⚡ **Lightning-Fast Network Scanning Tool — Written in Go**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-byte--err404-red?style=flat-square)](https://github.com/byte-err404)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)]()

</div>

---

## 📌 Overview

**Butescan** is a high-performance network scanner built in Go, inspired by **Nmap** and **RustScan**.
It combines blazing-fast concurrent port scanning with service detection, OS fingerprinting,
CVE vulnerability lookup, and a built-in script engine — all in a single binary.

---

## 🚀 Features

| Feature                  | Description                                              |
|--------------------------|----------------------------------------------------------|
| ⚡ Fast Port Scanning     | Concurrent TCP/UDP scanning with configurable thread pool |
| 🔍 Service Detection      | Auto-detects 30+ services from banners                   |
| 🏷️ Version Detection      | Extracts service version strings from responses          |
| 🖥️ OS Fingerprinting      | Detects OS via banner, TTL, and port combinations        |
| 🎯 Banner Grabbing        | Captures raw service banners for analysis                |
| 🛡️ CVE Lookup             | Online (NVD API) + offline built-in CVE database         |
| 📜 Script Engine          | 20+ built-in NSE-style scripts (HTTP, SSH, Redis, etc.)  |
| 🌐 CIDR / Multi-target   | Scan entire subnets or comma-separated hosts             |
| 📊 Report Formats         | Export as `text`, `json`, or `html`                      |

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/byte-err404/butescan.git
cd butescan

# Install dependencies
go mod tidy

# Build
chmod +x build.sh
./build.sh
```

> **Requirements:** Go 1.21+ → https://go.dev/dl/

---

## ▶️ Usage

### Basic Scan
```bash
sudo ./butescan -t 192.168.1.1
```

### Full Aggressive Scan (all features)
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 --os --cve --banner -v
```

### Subnet Scan
```bash
sudo ./butescan -t 192.168.0.0/24 --top-ports 100
```

### Script Scan
```bash
sudo ./butescan -t example.com --script http-headers,ssl-cert,ftp-anon
```

### Save Report
```bash
sudo ./butescan -t 192.168.1.1 --format html --output report.html
sudo ./butescan -t 192.168.1.1 --format json --output scan.json
```

---

## 🧩 All Flags

```
  -t, --target        Target host / IP / CIDR range       (required)
  -p, --ports         Port range: 80,443 or 1-65535 or top (default: 1-1024)
      --top-ports     Scan top N most common ports
  -c, --threads       Concurrent threads                   (default: 1000)
  -T, --timeout       Timeout in milliseconds              (default: 1000)
  -s, --scan-type     tcp | syn | udp | all                (default: tcp)
      --banner        Enable banner grabbing               (default: true)
      --os            Enable OS detection
      --cve           Enable CVE vulnerability lookup
      --script        Scripts to run (comma-separated)
  -o, --output        Output file path
      --format        Output format: text | json | html
  -v, --verbose       Verbose output
```

---

## 📜 Built-in Scripts

### 🌐 HTTP / HTTPS
| Script            | Description                                       |
|-------------------|---------------------------------------------------|
| `http-headers`    | Dump all HTTP response headers                    |
| `http-title`      | Extract HTML page title                           |
| `http-methods`    | Detect dangerous methods (PUT, DELETE, TRACE)     |
| `http-robots`     | Read robots.txt for hidden paths                  |
| `ssl-cert`        | TLS certificate info + expiry check               |
| `ssl-heartbleed`  | Check CVE-2014-0160 (Heartbleed)                  |

### 🔐 Services
| Script              | Description                                     |
|---------------------|-------------------------------------------------|
| `ssh-hostkey`       | SSH banner and host key info                    |
| `ssh-auth-methods`  | SSH authentication methods                      |
| `ftp-anon`          | Test anonymous FTP login                        |
| `smtp-commands`     | SMTP EHLO supported extensions                  |
| `smtp-open-relay`   | Test for open mail relay                        |
| `mysql-info`        | MySQL version from handshake                    |
| `redis-info`        | Redis INFO command (unauthenticated check)      |
| `redis-unauth`      | Test unauthenticated Redis key access           |
| `mongodb-info`      | MongoDB version / unauthenticated access check  |
| `vnc-info`          | VNC version and authentication type             |
| `telnet-ntlm-info`  | Telnet banner (insecure protocol warning)       |
| `snmp-info`         | SNMP public community string check              |
| `dns-brute`         | DNS subdomain brute-force (common wordlist)     |

---

## 📦 Output Formats

| Format  | Flag              | Description                          |
|---------|-------------------|--------------------------------------|
| `text`  | `--format text`   | Human-readable terminal output       |
| `json`  | `--format json`   | Machine-readable structured JSON     |
| `html`  | `--format html`   | Dark-themed interactive HTML report  |

---

## 🛡️ CVE Database

Butescan includes both **online** and **offline** CVE lookup:

- **Online:** Queries the [NVD REST API v2.0](https://nvd.nist.gov/developers/vulnerabilities) in real-time
- **Offline:** Built-in database covering 50+ critical CVEs across Apache, nginx, SSH, Redis, SMB, RDP, Log4Shell, Spring4Shell, and more

```bash
# Enable CVE lookup
sudo ./butescan -t 192.168.1.1 --cve

# Optional: set NVD API key for higher rate limits
export NVD_API_KEY=your-key-here
```

> Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

---

## 📸 Example Output

```
╔══════════════════════════════════════════════════╗
║  Host: 192.168.1.10                              ║
║  OS:   Linux (Ubuntu)                            ║
╚══════════════════════════════════════════════════╝

  PORT       STATE    SERVICE              VERSION             BANNER
  ─────────────────────────────────────────────────────────────────────
  22/tcp     open     ssh                  OpenSSH 8.9p1       SSH-2.0-OpenSSH_8.9p1
  80/tcp     open     http                 Apache 2.4.49       HTTP/1.1 200 OK
  443/tcp    open     https                nginx 1.22.0        HTTP/1.1 200 OK
  3306/tcp   open     mysql                MySQL 5.7.38        ...
  6379/tcp   open     redis                                     +PONG  [3 CVEs]
             └─ CVE-2022-0543  Lua sandbox escape → RCE   (CVSS: 10.0)
             └─ CVE-2021-32761 Integer overflow in GETDEL  (CVSS: 7.5)
             └─ CVE-2023-41056 Heap overflow in listpack   (CVSS: 8.1)
```

---

## ⚠️ Notes

- **SYN scan** (`--scan-type syn`) requires **root / Administrator** privileges
- **UDP scan** is significantly slower than TCP by nature
- CVE lookup makes external HTTP requests to the NVD API
- Rate limit for NVD API without key: **5 requests / 30 seconds**

---

## 👨‍💻 Author

**byte-err404**
> Built for educational purposes, CTFs, and authorized penetration testing.

---

## ⚖️ Disclaimer

> **This tool is intended for educational purposes and authorized security testing only.**
> Scanning systems without explicit permission may be illegal in your jurisdiction.
> The author is not responsible for any misuse or damage caused by this tool.
> **Always obtain proper authorization before scanning any system.**
