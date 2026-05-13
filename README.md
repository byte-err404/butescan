---
 
 ██████╗ ██╗   ██╗████████╗███████╗
 ██╔══██╗██║   ██║╚══██╔══╝██╔════╝
 ██████╔╝██║   ██║   ██║   █████╗
 ██╔══██╗██║   ██║   ██║   ██╔══╝
 ██████╔╝╚██████╔╝   ██║   ███████╗
 ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

---


---

### ⚡ Lightning-Fast Network Scanning Tool

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)

</div>

---

## 📌 Overview

**Butescan** is a high-performance Go-based network scanner inspired by Nmap & RustScan.  
It provides fast scanning, service detection, and vulnerability enumeration.

---

## 🚀 Features

- TCP / UDP scanning  
- Service & version detection  
- OS fingerprinting  
- Banner grabbing  
- CVE lookup  
- Script engine support  
- Multiple output formats  

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/butescan.git
cd butescan
go mod tidy
chmod +x build.sh
./build.sh
▶️ Usage
Basic Scan
sudo ./butescan -t 192.168.1.1
Full Scan
sudo ./butescan -t 192.168.1.1 -p 1-65535 -A --cve
Subnet Scan
sudo ./butescan -t 192.168.0.0/24 --top-ports 100
Script Scan
sudo ./butescan -t example.com --script http-headers,ssl-cert
📦 Output Formats
text
json
html
⚠️ Notes
SYN scan requires root
UDP is slower than TCP
Use only authorized systems
👨‍💻 Author

byte-err404

⚖️ Disclaimer

This tool is for educational and authorized security testing only.
````
