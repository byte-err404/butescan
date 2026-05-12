package scripts

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Engine runs built-in and custom scripts against open ports
type Engine struct {
	timeout time.Duration
	scripts map[string]ScriptFunc
}

// ScriptFunc is the type for script functions
type ScriptFunc func(host string, port int, service string) (string, error)

// New creates a new script engine with all built-in scripts registered
func New() *Engine {
	e := &Engine{
		timeout: 5 * time.Second,
		scripts: make(map[string]ScriptFunc),
	}

	// Register all built-in scripts
	e.scripts["http-headers"] = scriptHTTPHeaders
	e.scripts["http-title"] = scriptHTTPTitle
	e.scripts["http-methods"] = scriptHTTPMethods
	e.scripts["http-robots"] = scriptHTTPRobots
	e.scripts["ssh-auth-methods"] = scriptSSHAuthMethods
	e.scripts["ssh-hostkey"] = scriptSSHHostKey
	e.scripts["ftp-anon"] = scriptFTPAnon
	e.scripts["smtp-commands"] = scriptSMTPCommands
	e.scripts["smtp-open-relay"] = scriptSMTPOpenRelay
	e.scripts["mysql-info"] = scriptMySQLInfo
	e.scripts["redis-info"] = scriptRedisInfo
	e.scripts["redis-unauth"] = scriptRedisUnauth
	e.scripts["mongodb-info"] = scriptMongoDBInfo
	e.scripts["ssl-cert"] = scriptSSLCert
	e.scripts["ssl-heartbleed"] = scriptSSLHeartbleed
	e.scripts["dns-brute"] = scriptDNSBrute
	e.scripts["snmp-info"] = scriptSNMPInfo
	e.scripts["vnc-info"] = scriptVNCInfo
	e.scripts["telnet-ntlm-info"] = scriptTelnetInfo

	return e
}

// List returns all available script names
func (e *Engine) List() []string {
	names := make([]string, 0, len(e.scripts))
	for name := range e.scripts {
		names = append(names, name)
	}
	return names
}

// Run executes a script by name
func (e *Engine) Run(scriptName, host string, port int, service string) (string, error) {
	fn, ok := e.scripts[scriptName]
	if !ok {
		return "", fmt.Errorf("script '%s' not found", scriptName)
	}

	// Check if script applies to this service/port
	if !scriptApplies(scriptName, port, service) {
		return "", nil
	}

	result, err := fn(host, port, service)
	return result, err
}

// scriptApplies checks whether a script should run on a given port/service
func scriptApplies(script string, port int, service string) bool {
	svcLower := strings.ToLower(service)

	rules := map[string]func() bool{
		"http-headers":     func() bool { return isHTTP(port, svcLower) },
		"http-title":       func() bool { return isHTTP(port, svcLower) },
		"http-methods":     func() bool { return isHTTP(port, svcLower) },
		"http-robots":      func() bool { return isHTTP(port, svcLower) },
		"ssl-cert":         func() bool { return isHTTPS(port, svcLower) },
		"ssl-heartbleed":   func() bool { return isHTTPS(port, svcLower) },
		"ssh-auth-methods": func() bool { return svcLower == "ssh" || port == 22 },
		"ssh-hostkey":      func() bool { return svcLower == "ssh" || port == 22 },
		"ftp-anon":         func() bool { return svcLower == "ftp" || port == 21 },
		"smtp-commands":    func() bool { return svcLower == "smtp" || port == 25 || port == 587 },
		"smtp-open-relay":  func() bool { return svcLower == "smtp" || port == 25 },
		"mysql-info":       func() bool { return svcLower == "mysql" || port == 3306 },
		"redis-info":       func() bool { return svcLower == "redis" || port == 6379 },
		"redis-unauth":     func() bool { return svcLower == "redis" || port == 6379 },
		"mongodb-info":     func() bool { return svcLower == "mongodb" || port == 27017 },
		"dns-brute":        func() bool { return svcLower == "dns" || port == 53 },
		"snmp-info":        func() bool { return port == 161 },
		"vnc-info":         func() bool { return svcLower == "vnc" || port == 5900 },
		"telnet-ntlm-info": func() bool { return svcLower == "telnet" || port == 23 },
	}

	if rule, ok := rules[script]; ok {
		return rule()
	}
	return false
}

func isHTTP(port int, service string) bool {
	return port == 80 || port == 8080 || port == 8000 || port == 8888 ||
		strings.Contains(service, "http") && !strings.Contains(service, "https")
}

func isHTTPS(port int, service string) bool {
	return port == 443 || port == 8443 || strings.Contains(service, "https")
}

// ─── BUILT-IN SCRIPTS ─────────────────────────────────────────────────────────

func scriptHTTPHeaders(host string, port int, service string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := "http"
	if isHTTPS(port, service) {
		scheme = "https"
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/", scheme, host, port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Response: %s\n", resp.Status))
	for key, vals := range resp.Header {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", key, strings.Join(vals, ", ")))
	}
	return sb.String(), nil
}

func scriptHTTPTitle(host string, port int, service string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	scheme := "http"
	if isHTTPS(port, service) {
		scheme = "https"
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/", scheme, host, port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", err
	}

	bodyStr := string(body)
	title := extractHTMLTag(bodyStr, "title")
	if title != "" {
		return fmt.Sprintf("Page Title: %s", title), nil
	}
	return "No title found", nil
}

func scriptHTTPMethods(host string, port int, service string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	scheme := "http"
	if isHTTPS(port, service) {
		scheme = "https"
	}

	req, _ := http.NewRequest("OPTIONS", fmt.Sprintf("%s://%s:%d/", scheme, host, port), nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if allow != "" {
		dangerous := []string{}
		for _, m := range strings.Split(allow, ",") {
			m = strings.TrimSpace(m)
			if m == "PUT" || m == "DELETE" || m == "TRACE" || m == "CONNECT" {
				dangerous = append(dangerous, m)
			}
		}
		result := fmt.Sprintf("Allowed methods: %s", allow)
		if len(dangerous) > 0 {
			result += fmt.Sprintf("\n  [!] Potentially dangerous: %s", strings.Join(dangerous, ", "))
		}
		return result, nil
	}
	return "Could not determine allowed methods", nil
}

func scriptHTTPRobots(host string, port int, service string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	scheme := "http"
	if isHTTPS(port, service) {
		scheme = "https"
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/robots.txt", scheme, host, port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "No robots.txt found", nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Sprintf("robots.txt content:\n%s", string(body)), nil
}

func scriptSSHAuthMethods(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", fmt.Errorf("no SSH banner")
	}

	banner := strings.TrimSpace(string(buf[:n]))
	return fmt.Sprintf("SSH Banner: %s\nNote: Use ssh -v to enumerate auth methods", banner), nil
}

func scriptSSHHostKey(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 512)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)

	if n > 0 {
		return fmt.Sprintf("SSH Banner: %s", strings.TrimSpace(string(buf[:n]))), nil
	}
	return "", nil
}

func scriptFTPAnon(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	// Try anonymous login
	fmt.Fprintf(conn, "USER anonymous\r\n")
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ = conn.Read(buf)
	userResp := string(buf[:n])

	if strings.HasPrefix(userResp, "331") {
		fmt.Fprintf(conn, "PASS anonymous@test.com\r\n")
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		n, _ = conn.Read(buf)
		passResp := string(buf[:n])

		if strings.HasPrefix(passResp, "230") {
			// Successful anon login - list directory
			fmt.Fprintf(conn, "LIST\r\n")
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			n, _ = conn.Read(buf)
			return fmt.Sprintf("[VULNERABLE] Anonymous FTP login allowed!\nBanner: %s\nDirectory listing available", strings.TrimSpace(banner)), nil
		}
	}

	return fmt.Sprintf("Anonymous FTP login: DENIED\nBanner: %s", strings.TrimSpace(banner)), nil
}

func scriptSMTPCommands(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	// Send EHLO
	fmt.Fprintf(conn, "EHLO scanner.local\r\n")
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ = conn.Read(buf)
	ehlo := string(buf[:n])

	return fmt.Sprintf("Banner: %s\nSupported extensions:\n%s",
		strings.TrimSpace(banner), ehlo), nil
}

func scriptSMTPOpenRelay(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 512)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Read(buf) // Read banner

	fmt.Fprintf(conn, "EHLO test.example.com\r\n")
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Read(buf)

	fmt.Fprintf(conn, "MAIL FROM:<test@external.com>\r\n")
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	mailResp := string(buf[:n])

	fmt.Fprintf(conn, "RCPT TO:<victim@another-external.com>\r\n")
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	n, _ = conn.Read(buf)
	rcptResp := string(buf[:n])

	if strings.HasPrefix(rcptResp, "250") {
		return fmt.Sprintf("[VULNERABLE] Open mail relay detected!\nMAIL FROM response: %s\nRCPT TO response: %s",
			strings.TrimSpace(mailResp), strings.TrimSpace(rcptResp)), nil
	}

	return fmt.Sprintf("Open relay: NOT detected\nRCPT TO response: %s", strings.TrimSpace(rcptResp)), nil
}

func scriptMySQLInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)

	if n > 4 {
		// Parse MySQL handshake packet
		version := ""
		data := buf[4:n]
		if len(data) > 1 {
			// Protocol version byte then null-terminated version string
			nullIdx := strings.Index(string(data[1:]), "\x00")
			if nullIdx > 0 {
				version = string(data[1 : nullIdx+1])
			}
		}
		if version != "" {
			return fmt.Sprintf("MySQL Version: %s", version), nil
		}
	}

	return fmt.Sprintf("MySQL banner received (%d bytes)", n), nil
}

func scriptRedisInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send INFO command
	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")
	buf := make([]byte, 4096)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	response := string(buf[:n])
	if strings.HasPrefix(response, "-NOAUTH") || strings.HasPrefix(response, "-ERR") {
		return "Redis requires authentication (AUTH command needed)", nil
	}

	// Extract key info
	var result strings.Builder
	result.WriteString("[!] Redis accessible without authentication!\n")
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(line, "redis_version:") ||
			strings.HasPrefix(line, "os:") ||
			strings.HasPrefix(line, "connected_clients:") ||
			strings.HasPrefix(line, "used_memory_human:") {
			result.WriteString("  " + line + "\n")
		}
	}
	return result.String(), nil
}

func scriptRedisUnauth(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Try to get all keys
	fmt.Fprintf(conn, "*1\r\n$4\r\nKEYS\r\n*1\r\n$1\r\n*\r\n")
	buf := make([]byte, 2048)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	if strings.Contains(response, "NOAUTH") {
		return "Redis: Authentication required", nil
	}

	return fmt.Sprintf("[VULNERABLE] Unauthenticated Redis access! Response:\n%s",
		response[:min(200, len(response))]), nil
}

func scriptMongoDBInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send MongoDB isMaster command
	// OP_QUERY message
	isMasterCmd := []byte{
		// Message header (16 bytes)
		0x3f, 0x00, 0x00, 0x00, // messageLength
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode = OP_QUERY (2004)
		// OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd\0"
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// BSON document: {isMaster: 1}
		0x13, 0x00, 0x00, 0x00,
		0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00,
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(isMasterCmd)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return "MongoDB port open (could not parse response)", nil
	}

	return fmt.Sprintf("MongoDB responding (%d bytes) - may be accessible without auth. Use mongosh to verify.", n), nil
}

func scriptSSLCert(host string, port int, service string) (string, error) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", host, port),
		cfg,
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "No certificate found", nil
	}

	cert := certs[0]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Subject:    %s\n", cert.Subject.CommonName))
	sb.WriteString(fmt.Sprintf("Issuer:     %s\n", cert.Issuer.CommonName))
	sb.WriteString(fmt.Sprintf("Valid From: %s\n", cert.NotBefore.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("Valid To:   %s\n", cert.NotAfter.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("SANs:       %s\n", strings.Join(cert.DNSNames, ", ")))

	// Check expiry
	if time.Now().After(cert.NotAfter) {
		sb.WriteString("[!] Certificate is EXPIRED!\n")
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		sb.WriteString(fmt.Sprintf("[!] Certificate expires in %d days!\n",
			int(time.Until(cert.NotAfter).Hours()/24)))
	}

	return sb.String(), nil
}

func scriptSSLHeartbleed(host string, port int, service string) (string, error) {
	// Simplified Heartbleed check (CVE-2014-0160)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send ClientHello
	hello := buildTLSClientHello()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(hello)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "Could not establish TLS connection", nil
	}

	// Send Heartbeat request
	heartbeat := []byte{
		0x18, 0x03, 0x02,       // TLS heartbeat, TLS 1.1
		0x00, 0x03,             // Length 3
		0x01,                   // Heartbeat request
		0x40, 0x00,             // Payload length 16384
	}
	conn.Write(heartbeat)

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		return "Not vulnerable to Heartbleed (connection closed)", nil
	}

	if n > 0 && buf[0] == 0x18 {
		return "[VULNERABLE] Server may be vulnerable to Heartbleed (CVE-2014-0160)!", nil
	}

	return "Not vulnerable to Heartbleed", nil
}

func buildTLSClientHello() []byte {
	return []byte{
		0x16, 0x03, 0x01, 0x00, 0xdc, // TLS Record Header
		0x01, 0x00, 0x00, 0xd8,       // Handshake: ClientHello
		0x03, 0x02,                   // TLS 1.1
		// Random (32 bytes)
		0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
		0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
		0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
		0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
		0x00,             // Session ID Length
		0x00, 0x66,       // Cipher Suites Length
		// Cipher suites
		0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
		0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
		0x01, 0x00,       // Compression
	}
}

func scriptDNSBrute(host string, port int, service string) (string, error) {
	// Common subdomains to check
	subdomains := []string{"www", "mail", "ftp", "smtp", "pop", "imap", "admin", "vpn",
		"remote", "dev", "staging", "api", "portal", "webmail", "ns1", "ns2"}

	var found []string
	for _, sub := range subdomains {
		target := fmt.Sprintf("%s.%s", sub, host)
		addrs, err := net.LookupHost(target)
		if err == nil && len(addrs) > 0 {
			found = append(found, fmt.Sprintf("%s -> %s", target, strings.Join(addrs, ", ")))
		}
	}

	if len(found) == 0 {
		return "No subdomains found in wordlist", nil
	}

	return "Found subdomains:\n  " + strings.Join(found, "\n  "), nil
}

func scriptSNMPInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// SNMP v1 GetRequest for sysDescr
	snmpGet := []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
		0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
		0x04, 0x71, 0xb4, 0x10, 0x45, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
		0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(snmpGet)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "SNMP: No response (may require auth)", nil
	}

	return fmt.Sprintf("SNMP responding with community 'public' (%d bytes)\n[!] Public community string may be accessible!", n), nil
}

func scriptVNCInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 64)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", fmt.Errorf("no VNC banner")
	}

	banner := string(buf[:n])
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VNC Protocol: %s\n", strings.TrimSpace(banner)))

	// Check for no-auth
	if strings.Contains(banner, "RFB 003.008") || strings.Contains(banner, "RFB 003.007") {
		sb.WriteString("Version supports None authentication (may be accessible without password)")
	}

	return sb.String(), nil
}

func scriptTelnetInfo(host string, port int, service string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)

	if n > 0 {
		return fmt.Sprintf("[!] Telnet is enabled (insecure protocol!)\nBanner: %s",
			cleanASCII(string(buf[:n]))), nil
	}

	return "Telnet port open", nil
}

func extractHTMLTag(html, tag string) string {
	htmlLower := strings.ToLower(html)
	openTag := "<" + tag
	closeTag := "</" + tag + ">"

	start := strings.Index(htmlLower, openTag)
	if start == -1 {
		return ""
	}

	// Find end of opening tag
	tagEnd := strings.Index(htmlLower[start:], ">")
	if tagEnd == -1 {
		return ""
	}
	contentStart := start + tagEnd + 1

	end := strings.Index(htmlLower[contentStart:], closeTag)
	if end == -1 {
		return ""
	}

	content := html[contentStart : contentStart+end]
	return strings.TrimSpace(content)
}

func cleanASCII(s string) string {
	var clean strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' {
			clean.WriteRune(r)
		}
	}
	return strings.TrimSpace(clean.String())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
