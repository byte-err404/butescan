package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Config holds scanner configuration
type Config struct {
	Host       string
	Ports      []int
	Timeout    time.Duration
	Threads    int
	ScanType   string
	BannerGrab bool
	Verbose    bool
}

// PortResult holds result for a single port
type PortResult struct {
	Port         int
	Protocol     string
	State        string
	Service      string
	Version      string
	Banner       string
	CVEs         []CVEInfo
	ScriptOutput []string
}

// CVEInfo holds CVE data (populated by cve package)
type CVEInfo struct {
	ID          string
	Score       float64
	Description string
	CVSS        string
	Published   string
}

// ScanResult holds full scan results for a host
type ScanResult struct {
	Host      string
	IP        string
	OS        string
	StartTime time.Time
	EndTime   time.Time
	OpenPorts []PortResult
}

// Scanner is the main scanning engine
type Scanner struct {
	cfg *Config
}

// New creates a new Scanner
func New(cfg *Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Scan performs the full scan
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Host:      s.cfg.Host,
		StartTime: time.Now(),
	}

	// Resolve IP
	ip, err := net.ResolveIPAddr("ip", s.cfg.Host)
	if err == nil {
		result.IP = ip.String()
	}

	// Channel-based concurrent scanning
	portCh := make(chan int, len(s.cfg.Ports))
	resultCh := make(chan PortResult, len(s.cfg.Ports))

	// Feed ports
	for _, p := range s.cfg.Ports {
		portCh <- p
	}
	close(portCh)

	// Worker pool
	var wg sync.WaitGroup
	threads := s.cfg.Threads
	if threads > len(s.cfg.Ports) {
		threads = len(s.cfg.Ports)
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				// TCP scan
				if s.cfg.ScanType == "tcp" || s.cfg.ScanType == "all" || s.cfg.ScanType == "syn" {
					if pr, open := s.scanTCP(port); open {
						resultCh <- pr
					}
				}
				// UDP scan
				if s.cfg.ScanType == "udp" || s.cfg.ScanType == "all" {
					if pr, open := s.scanUDP(port); open {
						resultCh <- pr
					}
				}
			}
		}()
	}

	// Close result channel when done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	for pr := range resultCh {
		result.OpenPorts = append(result.OpenPorts, pr)
	}

	// Sort by port number
	sortPorts(result.OpenPorts)

	result.EndTime = time.Now()
	return result, nil
}

// scanTCP performs a TCP connect scan on a port
func (s *Scanner) scanTCP(port int) (PortResult, bool) {
	address := fmt.Sprintf("%s:%d", s.cfg.Host, port)
	conn, err := net.DialTimeout("tcp", address, s.cfg.Timeout)
	if err != nil {
		return PortResult{}, false
	}
	defer conn.Close()

	pr := PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
	}

	// Banner grabbing
	if s.cfg.BannerGrab {
		banner := grabBanner(conn, port, s.cfg.Timeout)
		pr.Banner = cleanBanner(banner)
		pr.Service, pr.Version = detectService(port, banner)
	} else {
		pr.Service, pr.Version = detectService(port, "")
	}

	return pr, true
}

// scanUDP performs a UDP scan
func (s *Scanner) scanUDP(port int) (PortResult, bool) {
	address := fmt.Sprintf("%s:%d", s.cfg.Host, port)
	conn, err := net.DialTimeout("udp", address, s.cfg.Timeout)
	if err != nil {
		return PortResult{}, false
	}
	defer conn.Close()

	// Send probe
	conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	probe := udpProbe(port)
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	// If we get a response, port is open
	if err == nil && n > 0 {
		pr := PortResult{
			Port:     port,
			Protocol: "udp",
			State:    "open",
			Banner:   cleanBanner(string(buf[:n])),
		}
		pr.Service, pr.Version = detectService(port, pr.Banner)
		return pr, true
	}

	// For UDP, no response might mean open|filtered for certain ports
	if isCommonUDP(port) {
		pr := PortResult{
			Port:     port,
			Protocol: "udp",
			State:    "open|filtered",
		}
		pr.Service, _ = detectService(port, "")
		return pr, true
	}

	return PortResult{}, false
}

// grabBanner attempts to grab the service banner
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))

	// Send HTTP probe for web ports
	if port == 80 || port == 8080 || port == 8000 || port == 8888 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n")
	} else if port == 443 || port == 8443 {
		// For HTTPS, just read initial data
	} else if port == 21 || port == 22 || port == 25 || port == 110 ||
		port == 143 || port == 220 || port == 587 {
		// These services send banner first, just read
	} else {
		// Generic probe
		fmt.Fprintf(conn, "\r\n")
	}

	buf := make([]byte, 2048)
	conn.SetDeadline(time.Now().Add(timeout / 2))
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

// cleanBanner sanitizes the banner string
func cleanBanner(banner string) string {
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.TrimSpace(banner)
	// Remove non-printable chars
	var clean strings.Builder
	for _, r := range banner {
		if r >= 32 && r < 127 {
			clean.WriteRune(r)
		}
	}
	result := clean.String()
	if len(result) > 256 {
		result = result[:256]
	}
	return result
}

// Service fingerprint database
type serviceFingerprint struct {
	service string
	version string
	probes  []string
}

var serviceDB = map[int]serviceFingerprint{
	21:    {service: "ftp", probes: []string{"220", "FTP", "ProFTPD", "vsftpd", "FileZilla"}},
	22:    {service: "ssh", probes: []string{"SSH", "OpenSSH", "Dropbear", "libssh"}},
	23:    {service: "telnet", probes: []string{"Telnet", "login"}},
	25:    {service: "smtp", probes: []string{"SMTP", "Postfix", "Exim", "Sendmail", "220"}},
	53:    {service: "dns"},
	80:    {service: "http", probes: []string{"HTTP", "Server:", "Apache", "nginx", "IIS", "Tomcat"}},
	110:   {service: "pop3", probes: []string{"POP3", "+OK"}},
	111:   {service: "rpcbind"},
	135:   {service: "msrpc"},
	139:   {service: "netbios-ssn"},
	143:   {service: "imap", probes: []string{"IMAP", "Dovecot", "* OK"}},
	443:   {service: "https", probes: []string{"HTTP", "Server:", "Apache", "nginx"}},
	445:   {service: "microsoft-ds"},
	587:   {service: "smtp-submission"},
	993:   {service: "imaps"},
	995:   {service: "pop3s"},
	1521:  {service: "oracle", probes: []string{"Oracle", "TNS"}},
	1723:  {service: "pptp"},
	2181:  {service: "zookeeper", probes: []string{"Zookeeper", "imok"}},
	2379:  {service: "etcd"},
	3306:  {service: "mysql", probes: []string{"MySQL", "MariaDB", "mysql_native_password"}},
	3389:  {service: "ms-wbt-server"},
	4369:  {service: "epmd"},
	5432:  {service: "postgresql", probes: []string{"PostgreSQL", "pg_hba"}},
	5672:  {service: "amqp", probes: []string{"AMQP", "RabbitMQ"}},
	5900:  {service: "vnc", probes: []string{"RFB", "VNC"}},
	6379:  {service: "redis", probes: []string{"redis_version", "PONG", "+PONG"}},
	6443:  {service: "kubernetes-api"},
	8080:  {service: "http-proxy", probes: []string{"HTTP", "Server:"}},
	8443:  {service: "https-alt"},
	8888:  {service: "http-alt"},
	9200:  {service: "elasticsearch", probes: []string{"elasticsearch", "cluster_name"}},
	9300:  {service: "elasticsearch-cluster"},
	11211: {service: "memcached", probes: []string{"memcached", "STAT"}},
	15672: {service: "rabbitmq-management"},
	27017: {service: "mongodb", probes: []string{"MongoDB", "mongod", "ismaster"}},
	61616: {service: "activemq"},
}

// detectService identifies the service and version from port + banner
func detectService(port int, banner string) (service, version string) {
	// Check service DB
	if fp, ok := serviceDB[port]; ok {
		service = fp.service

		// Try to extract version from banner
		if banner != "" {
			version = extractVersion(banner, fp.probes)
		}
		return
	}

	// Fallback: detect from banner content
	bannerLower := strings.ToLower(banner)
	switch {
	case strings.Contains(bannerLower, "apache"):
		service = "http"
		version = extractVersionFromString(banner, "Apache/")
	case strings.Contains(bannerLower, "nginx"):
		service = "http"
		version = extractVersionFromString(banner, "nginx/")
	case strings.Contains(bannerLower, "openssh"):
		service = "ssh"
		version = extractVersionFromString(banner, "OpenSSH_")
	case strings.Contains(bannerLower, "mysql"):
		service = "mysql"
	case strings.Contains(bannerLower, "postgresql"):
		service = "postgresql"
	case strings.Contains(bannerLower, "redis"):
		service = "redis"
	case strings.Contains(bannerLower, "mongodb"):
		service = "mongodb"
	default:
		service = "unknown"
	}
	return
}

func extractVersion(banner string, probes []string) string {
	for _, probe := range probes {
		idx := strings.Index(banner, probe)
		if idx >= 0 {
			// Try to extract version number after probe keyword
			rest := banner[idx+len(probe):]
			rest = strings.TrimLeft(rest, " /:")
			words := strings.Fields(rest)
			if len(words) > 0 {
				// Find first word that looks like a version
				for _, w := range words {
					if len(w) > 0 && (w[0] >= '0' && w[0] <= '9') {
						// Take up to next space or special char
						ver := ""
						for _, c := range w {
							if c == ' ' || c == ',' || c == ')' || c == '(' {
								break
							}
							ver += string(c)
						}
						if ver != "" {
							return probe + " " + ver
						}
					}
				}
				if len(words[0]) < 40 {
					return probe + " " + words[0]
				}
			}
		}
	}
	return ""
}

func extractVersionFromString(banner, prefix string) string {
	idx := strings.Index(banner, prefix)
	if idx < 0 {
		return ""
	}
	rest := banner[idx+len(prefix):]
	end := strings.IndexAny(rest, " \r\n\t()")
	if end > 0 {
		return rest[:end]
	}
	if len(rest) < 20 {
		return rest
	}
	return rest[:20]
}

func udpProbe(port int) []byte {
	switch port {
	case 53:
		// DNS query for example.com
		return []byte{
			0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
			0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
			0x00, 0x00, 0x01, 0x00, 0x01,
		}
	case 161:
		// SNMP get
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
			0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
		}
	default:
		return []byte("\r\n")
	}
}

func isCommonUDP(port int) bool {
	commonUDP := map[int]bool{
		53: true, 67: true, 68: true, 69: true, 123: true,
		161: true, 162: true, 500: true, 514: true, 520: true,
		4500: true, 5353: true,
	}
	return commonUDP[port]
}

func sortPorts(ports []PortResult) {
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[i].Port > ports[j].Port {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
}
