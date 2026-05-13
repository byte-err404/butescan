# 🎯 Butescan - Complete Usage Guide

## এই গাইডটি যারা প্রথমবার Butescan ব্যবহার করছেন তাদের জন্য

---

## 📥 Step 1: Installation (ইনস্টলেশন)

### Linux/macOS এ Install করুন:

```bash
# Step 1: Repository clone করুন
git clone https://github.com/byte-err404/butescan.git
cd butescan

# Step 2: Build script চালান
chmod +x build.sh
./build.sh

# Step 3: Installation যাচাই করুন
./butescan -h
```

**উইন্ডোজ ইউজারদের জন্য:**
- WSL2 (Windows Subsystem for Linux) ব্যবহার করুন
- অথবা Linux VM ব্যবহার করুন

---

## 🚀 Step 2: প্রথম Scan চালানো

### সবচেয়ে সহজ উপায়:

```bash
# একটি হোস্ট স্ক্যান করুন (আপনার নিজের কম্পিউটার)
sudo ./butescan -t 127.0.0.1

# অথবা আপনার নেটওয়ার্ক এড্রেস
sudo ./butescan -t 192.168.1.1
```

**আউটপুট দেখবেন:**
```
[*] Targets: 1 | Ports: 1000 | Threads: 1000 | Timeout: 1000ms
[>] Scanning 127.0.0.1 ...

PORT     STATE    SERVICE          VERSION
22/tcp   open     ssh              OpenSSH 8.9
80/tcp   open     http             Apache 2.4.52
443/tcp  open     https            nginx 1.22
```

---

## 📚 Step 3: Common Commands শিখুন

### প্রথম 5 কমান্ড যা আপনি ব্যবহার করবেন:

#### 1️⃣ **সাধারণ স্ক্যান** (সবার জন্য)
```bash
sudo ./butescan -t 192.168.1.1
```
**এটি করে:** শীর্ষ 1000 পোর্ট স্ক্যান করে

---

#### 2️⃣ **সব পোর্ট স্ক্যান করা** (সম্পূর্ণ স্ক্যান)
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535
```
**এটি করে:** সব 65535 পোর্ট চেক করে (ধীর, কিন্তু সম্পূর্ণ)

---

#### 3️⃣ **দ্রুত স্ক্যান** (শুধু গুরুত্বপূর্ণ পোর্ট)
```bash
sudo ./butescan -t 192.168.1.1 --top-ports 100
```
**এটি করে:** সবচেয়ে সাধারণ 100 পোর্ট স্ক্যান করে (খুব দ্রুত)

---

#### 4️⃣ **সেবা শনাক্তকরণ** (সেবার নাম জানতে)
```bash
sudo ./butescan -t 192.168.1.1 -sV
```
**এটি করে:** SSH, Apache, nginx ইত্যাদি সেবার নাম দেখায়

---

#### 5️⃣ **OS ডিটেকশন** (অপারেটিং সিস্টেম জানতে)
```bash
sudo ./butescan -t 192.168.1.1 -O
```
**এটি করে:** Linux, Windows, macOS ইত্যাদি সনাক্ত করে

---

## 🎓 Step 4: আরও শক্তিশালী স্ক্যান

### Aggressive Scan (সবকিছু একসাথে)
```bash
sudo ./butescan -t 192.168.1.1 -A
```
**এটি করে:**
- ✅ সেবা শনাক্ত করে
- ✅ OS সনাক্ত করে
- ✅ Script চালায়
- ✅ সম্পূর্ণ তথ্য দেয়

---

### Stealth Scan (লুকানো স্ক্যান)
```bash
sudo ./butescan -t 192.168.1.1 -sS
```
**এটি করে:** SYN scan (খুব লুকানো, আগের সিস্টেম সনাক্ত করতে পারে না)

---

### UDP Scan (UDP সেবা খুঁজুন)
```bash
sudo ./butescan -t 192.168.1.1 -sU -p 53,123,161
```
**এটি করে:** DNS (53), NTP (123), SNMP (161) পরীক্ষা করে

---

## 💾 Step 5: রিপোর্ট সংরক্ষণ করা

### JSON ফরম্যাটে রিপোর্ট
```bash
sudo ./butescan -t 192.168.1.1 -A --format json -o scan-report.json
```
**ফলাফল:** `scan-report.json` ফাইল তৈরি হবে

---

### HTML রিপোর্ট (সুন্দর দেখতে)
```bash
sudo ./butescan -t 192.168.1.1 -A --format html -o scan-report.html
```
**ফলাফল:** ব্রাউজারে খুলে সুন্দর গ্রাফিক্স দেখতে পারবেন

---

## 🔒 Step 6: CVE (সিকিউরিটি হুমকি) খুঁজুন

### CVE লুকআপ চালু করুন
```bash
sudo ./butescan -t 192.168.1.1 -A --cve --format html -o report-with-cves.html
```

**আউটপুট উদাহরণ:**
```
[!] Port 6379/tcp: 3 CVE(s) found!
    CVE-2022-0543        CVSS:10.0  Redis Lua sandbox escape
    CVE-2021-32761       CVSS:7.5   Redis integer overflow
```

---

## 🎯 Step 7: স্ক্রিপ্ট চালানো (উন্নত তথ্য জন্য)

### সমস্ত HTTP scripts চালান
```bash
sudo ./butescan -t 192.168.1.1 -p 80,443 \
  --script http-headers,http-title,ssl-cert
```

---

### উপলব্ধ স্ক্রিপ্ট দেখুন
```bash
./butescan --help-scripts
```

**পাবেন:**
- ✅ http-headers (HTTP হেডার দেখান)
- ✅ ssl-cert (SSL সার্টিফিকেট তথ্য)
- ✅ ssh-hostkey (SSH key তথ্য)
- ✅ ftp-anon (Anonymous FTP লগইন)
- এবং আরও অনেক কিছু...

---

## 📊 Step 8: সাবনেট স্ক্যান করা (পুরো নেটওয়ার্ক)

### একটি নেটওয়ার্ক সম্পূর্ণ স্ক্যান করুন
```bash
sudo ./butescan -t 192.168.1.0/24 --top-ports 100 -A
```

**এটি করে:**
- 192.168.1.1 থেকে 192.168.1.254 পর্যন্ত সব হোস্ট স্ক্যান করে
- শীর্ষ 100 পোর্ট চেক করে
- সেবা এবং OS শনাক্ত করে

---

## ⚡ Step 9: পারফরম্যান্স টিউনিং

### দ্রুত স্ক্যান চান? (সবচেয়ে বেশি গতি)
```bash
sudo ./butescan -t 192.168.1.1 -p 1-65535 -c 5000 -T 500
```
**ব্যাখ্যা:**
- `-c 5000` = 5000টি একযোগে কানেকশন
- `-T 500` = 500ms টাইমআউট (অনেক কম)

---

### স্লো (মৃদু) স্ক্যান চান? (কোন সমস্যা এড়াতে)
```bash
sudo ./butescan -t 192.168.1.1 -p 1-10000 -c 100 -T 3000
```
**ব্যাখ্যা:**
- `-c 100` = মাত্র 100টি একসাথে
- `-T 3000` = 3000ms টাইমআউট (অনেক বেশি)

---

## 🔐 Step 10: সিকিউরিটি অডিট (সম্পূর্ণ পরীক্ষা)

### ওয়েব সার্ভার সিকিউরিটি চেক
```bash
sudo ./butescan -t example.com -p 80,443 -A \
  --script http-headers,http-methods,ssl-cert,ssl-heartbleed \
  --cve --format html -o web-security-audit.html
```

---

### ডাটাবেস সার্ভার চেক
```bash
sudo ./butescan -t db.internal -p 3306,5432,6379,27017 \
  --script mysql-info,redis-info,mongodb-info \
  --cve --format html -o database-audit.html
```

---

## 🚨 গুরুত্বপূর্ণ সতর্কতা

### ⚠️ শুধুমাত্র নিজের সিস্টেম স্ক্যান করুন!

```bash
# ✅ এটি ঠিক (নিজের কম্পিউটার)
sudo ./butescan -t 127.0.0.1
sudo ./butescan -t localhost
sudo ./butescan -t 192.168.1.1 (আপনার রাউটার)

# ❌ এটি বেআইনি (অন্যের সিস্টেম)
sudo ./butescan -t 8.8.8.8 (Google - অবৈধ!)
sudo ./butescan -t random-website.com (বিনা অনুমতিতে - অবৈধ!)
```

---

## 🎯 Real-World Examples

### উদাহরণ 1: আপনার হোম রাউটার চেক করুন
```bash
# প্রথমে আপনার রাউটার IP খুঁজুন (সাধারণত 192.168.1.1)
sudo ./butescan -t 192.168.1.1 -A --format html -o router-check.html

# ব্রাউজারে খুলুন: router-check.html
```

---

### উদাহরণ 2: লোকাল নেটওয়ার্ক অডিট
```bash
# আপনার সম্পূর্ণ নেটওয়ার্ক স্ক্যান করুন
sudo ./butescan -t 192.168.0.0/24 \
  --top-ports 100 \
  -A \
  --cve \
  --format html \
  -o network-full-audit.html
```

---

### উদাহরণ 3: দ্রুত vulnerability চেক
```bash
# শুধুমাত্র critical পোর্ট এবং CVE
sudo ./butescan -t 192.168.1.1 \
  -p 22,80,443,3306,6379 \
  -sV \
  --cve \
  --format json \
  -o quick-vuln-check.json
```

---

## 📖 Flag এর অর্থ

| Flag | মানে | উদাহরণ |
|------|------|--------|
| `-t` | Target (যা স্ক্যান করবেন) | `-t 192.168.1.1` |
| `-p` | Ports (কোন পোর্ট স্ক্যান করবেন) | `-p 80,443` |
| `-sS` | SYN Scan (লুকানো স্ক্যান) | `-sS` |
| `-sV` | Service Version Detection | `-sV` |
| `-O` | OS Detection | `-O` |
| `-A` | Aggressive (সবকিছু) | `-A` |
| `--cve` | CVE Lookup (দুর্বলতা খুঁজুন) | `--cve` |
| `--script` | Scripts চালান | `--script http-headers` |
| `-o` | Output (ফাইলে সংরক্ষণ করুন) | `-o report.html` |
| `--format` | Format (কোন ফরম্যাটে) | `--format html` |
| `-c` | Concurrency (একসাথে কতটি) | `-c 5000` |
| `-T` | Timeout (কতক্ষণ অপেক্ষা করবেন) | `-T 1000` |

---

## 🆘 সাধারণ সমস্যা সমাধান

### সমস্যা 1: "Permission denied" ত্রুটি
```bash
# ❌ এটি কাজ করবে না
./butescan -t 192.168.1.1 -sS

# ✅ এটি কাজ করবে
sudo ./butescan -t 192.168.1.1 -sS
```

---

### সমস্যা 2: স্ক্যান খুব ধীর
```bash
# ✅ সমাধান: থ্রেড বাড়ান
sudo ./butescan -t 192.168.1.1 -c 5000 -T 500
```

---

### সমস্যা 3: কোন পোর্ট খোলা দেখাচ্ছে না
```bash
# ✅ সমাধান: টাইমআউট বাড়ান
sudo ./butescan -t 192.168.1.1 -T 3000
```

---

### সমস্যা 4: CVE লুকআপ কাজ করছে না
```bash
# প্রথমে API key পান: https://nvd.nist.gov/developers/request-an-api-key
# তারপর এটি সেট করুন
export NVD_API_KEY=your-api-key-here

# এখন চালান
sudo ./butescan -t 192.168.1.1 --cve
```

---

## 💡 Pro Tips (পেশাদার পরামর্শ)

### Tip 1: ধাপে ধাপে স্ক্যান করুন
```bash
# প্রথম: দ্রুত স্ক্যান
sudo ./butescan -t 192.168.1.1 --top-ports 100

# দ্বিতীয়: সম্পূর্ণ স্ক্যান
sudo ./butescan -t 192.168.1.1 -p 1-65535

# তৃতীয়: সেবা এবং CVE
sudo ./butescan -t 192.168.1.1 -p 1-65535 -sV --cve
```

---

### Tip 2: রিপোর্ট তুলনা করুন
```bash
# প্রথম দিনে স্ক্যান
sudo ./butescan -t 192.168.1.1 --format json -o day1.json

# এক সপ্তাহ পর স্ক্যান
sudo ./butescan -t 192.168.1.1 --format json -o day7.json

# তুলনা করুন: day1.json এবং day7.json এর মধ্যে নতুন পোর্ট আছে কিনা
```

---

### Tip 3: বড় নেটওয়ার্ক স্ক্যান করার সময় মৃদু থাকুন
```bash
# ❌ এটি সমস্যা সৃষ্টি করতে পারে
sudo ./butescan -t 192.168.0.0/16 -c 10000

# ✅ এটি ভালো
sudo ./butescan -t 192.168.0.0/16 -c 500 --rate-limit 50
```

---

## 🎓 শেখার পথ

1. **প্রথম দিন:** প্রথম 5 কমান্ড শিখুন
2. **দ্বিতীয় দিন:** স্ক্রিপ্ট এবং CVE শিখুন
3. **তৃতীয় দিন:** পারফরম্যান্স টিউনিং শিখুন
4. **চতুর্থ দিন:** সিকিউরিটি অডিট প্র্যাকটিস করুন

---

## 📞 আরও সাহায্য চাইলে

- 📧 Email: support@butescan.dev
- 🐛 GitHub Issues: https://github.com/byte-err404/butescan/issues
- 💬 Discussion: https://github.com/byte-err404/butescan/discussions
- 📚 Wiki: https://github.com/byte-err404/butescan/wiki

---

**Happy Scanning! 🚀**
