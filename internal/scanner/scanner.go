package scanner

import (
	"fmt"
	"net"
	"sort"
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
	RateLimit  time.Duration
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
	Geo          string // Geolocation
	CPE          string // CPE identifier
}

// CVEInfo holds CVE data
type CVEInfo struct {
	ID          string
	Score       float64
	Description string
	CVSS        string
	Published   string
}

// ScanResult holds full scan results for a host
type ScanResult struct {
	Host       string
	IP         string
	OS         string
	OSCPE      string // CPE for OS
	StartTime  time.Time
	EndTime    time.Time
	OpenPorts  []PortResult
	Traceroute []string // Traceroute hops
	Hostname   string   // DNS reverse lookup
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

	// DNS Reverse lookup
	if s.cfg.Verbose {
		names, _ := net.LookupAddr(result.IP)
		if len(names) > 0 {
			result.Hostname = names[0]
		}
	}

	portCh := make(chan int, len(s.cfg.Ports))
	resultCh := make(chan PortResult, len(s.cfg.Ports))

	for _, p := range s.cfg.Ports {
		portCh <- p
	}
	close(portCh)

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

				if s.cfg.RateLimit > 0 {
					time.Sleep(s.cfg.RateLimit)
				}

				// TCP
				if s.cfg.ScanType == "tcp" ||
					s.cfg.ScanType == "syn" ||
					s.cfg.ScanType == "ack" ||
					s.cfg.ScanType == "window" ||
					s.cfg.ScanType == "maimon" ||
					s.cfg.ScanType == "idle" ||
					s.cfg.ScanType == "all" {

					if pr, open := s.scanTCP(port); open {
						resultCh <- pr
					}
				}

				// UDP
				if s.cfg.ScanType == "udp" ||
					s.cfg.ScanType == "all" {

					if pr, open := s.scanUDP(port); open {
						resultCh <- pr
					}
				}

				// SCTP
				if s.cfg.ScanType == "sctp" {
					if pr, open := s.scanSCTP(port); open {
						resultCh <- pr
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for pr := range resultCh {
		result.OpenPorts = append(result.OpenPorts, pr)
	}

	// Remove duplicates
	result.OpenPorts = removeDuplicatePorts(result.OpenPorts)

	// Sort ports
	sortPorts(result.OpenPorts)

	result.EndTime = time.Now()

	return result, nil
}

// scanTCP performs TCP connect scan
func (s *Scanner) scanTCP(port int) (PortResult, bool) {
	address := fmt.Sprintf("%s:%d", s.cfg.Host, port)

	conn, err := net.DialTimeout(
		"tcp",
		address,
		s.cfg.Timeout,
	)

	if err != nil {
		return PortResult{}, false
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.cfg.Timeout))

	pr := PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
	}

	if s.cfg.BannerGrab {
		banner := grabBanner(conn, port, s.cfg.Timeout)

		pr.Banner = cleanBanner(banner)

		pr.Service, pr.Version, pr.CPE = detectService(
			port,
			banner,
		)
	} else {
		pr.Service, pr.Version, pr.CPE = detectService(port, "")
	}

	return pr, true
}

// scanUDP performs UDP scan
func (s *Scanner) scanUDP(port int) (PortResult, bool) {
	address := fmt.Sprintf("%s:%d", s.cfg.Host, port)

	conn, err := net.DialTimeout(
		"udp",
		address,
		s.cfg.Timeout,
	)

	if err != nil {
		return PortResult{}, false
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.cfg.Timeout))

	probe := udpProbe(port)

	conn.Write(probe)

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		pr := PortResult{
			Port:     port,
			Protocol: "udp",
			State:    "open",
			Banner:   cleanBanner(string(buf[:n])),
		}

		pr.Service, pr.Version, pr.CPE = detectService(
			port,
			pr.Banner,
		)

		return pr, true
	}

	if isCommonUDP(port) {
		pr := PortResult{
			Port:     port,
			Protocol: "udp",
			State:    "open|filtered",
		}

		pr.Service, _, pr.CPE = detectService(port, "")

		return pr, true
	}

	return PortResult{}, false
}

// scanSCTP performs SCTP scan
func (s *Scanner) scanSCTP(port int) (PortResult, bool) {
	// SCTP scanning (basic implementation)
	// In production, use proper SCTP library
	return PortResult{}, false
}

// grabBanner grabs service banners
func grabBanner(
	conn net.Conn,
	port int,
	timeout time.Duration,
) string {

	conn.SetDeadline(time.Now().Add(timeout))

	// HTTP
	if port == 80 ||
		port == 8080 ||
		port == 8000 ||
		port == 8888 {

		fmt.Fprintf(
			conn,
			"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n",
		)

	} else if port == 443 || port == 8443 {

		fmt.Fprintf(
			conn,
			"HEAD / HTTP/1.0\r\n\r\n",
		)

	} else if port == 21 ||
		port == 22 ||
		port == 25 ||
		port == 110 ||
		port == 143 ||
		port == 220 ||
		port == 587 {

		// Banner comes automatically

	} else {

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

// cleanBanner sanitizes banners
func cleanBanner(banner string) string {
	banner = strings.ReplaceAll(
		banner,
		"\r\n",
		" ",
	)

	banner = strings.ReplaceAll(
		banner,
		"\n",
		" ",
	)

	banner = strings.TrimSpace(banner)

	var clean strings.Builder

	for _, r := range banner {

		if r >= 32 && r <= 126 {
			clean.WriteRune(r)
		}
	}

	result := clean.String()

	if len(result) > 256 {
		result = result[:256]
	}

	return result
}

type serviceFingerprint struct {
	service string
	version string
	cpe     string
	probes  []string
}

var serviceDB = map[int]serviceFingerprint{
	21:    {service: "ftp", cpe: "cpe:/a:vsftpd:vsftpd", probes: []string{"220", "FTP", "ProFTPD", "vsftpd"}},
	22:    {service: "ssh", cpe: "cpe:/a:libssh:libssh", probes: []string{"SSH", "OpenSSH"}},
	23:    {service: "telnet", cpe: "cpe:/o:linux:linux_kernel", probes: []string{"Telnet"}},
	25:    {service: "smtp", cpe: "cpe:/a:postfix:postfix", probes: []string{"SMTP", "Postfix"}},
	53:    {service: "dns", cpe: "cpe:/a:isc:bind"},
	80:    {service: "http", cpe: "cpe:/a:apache:http_server", probes: []string{"HTTP", "Apache", "nginx"}},
	110:   {service: "pop3", cpe: "cpe:/a:dovecot:dovecot"},
	143:   {service: "imap", cpe: "cpe:/a:dovecot:dovecot"},
	443:   {service: "https", cpe: "cpe:/a:apache:http_server", probes: []string{"HTTP", "HTTPS", "Apache", "nginx"}},
	445:   {service: "microsoft-ds", cpe: "cpe:/a:microsoft:windows_server"},
	3306:  {service: "mysql", cpe: "cpe:/a:mysql:mysql", probes: []string{"MySQL", "MariaDB"}},
	5432:  {service: "postgresql", cpe: "cpe:/a:postgresql:postgresql", probes: []string{"PostgreSQL"}},
	5900:  {service: "vnc", cpe: "cpe:/a:realvnc:vnc_server"},
	6379:  {service: "redis", cpe: "cpe:/a:redis:redis", probes: []string{"redis_version"}},
	8080:  {service: "http-proxy", cpe: "cpe:/a:apache:http_server"},
	8443:  {service: "https-alt", cpe: "cpe:/a:apache:http_server"},
	9200:  {service: "elasticsearch", cpe: "cpe:/a:elasticsearch:elasticsearch"},
	27017: {service: "mongodb", cpe: "cpe:/a:mongodb:mongodb"},
}

// detectService identifies services with CPE identifiers
func detectService(port int, banner string) (
	service,
	version,
	cpe string,
) {

	if fp, ok := serviceDB[port]; ok {

		service = fp.service
		cpe = fp.cpe

		if banner != "" {
			version = extractVersion(
				banner,
				fp.probes,
			)
		}

		return
	}

	bannerLower := strings.ToLower(banner)

	switch {

	case strings.Contains(bannerLower, "apache"):
		service = "http"
		cpe = "cpe:/a:apache:http_server"
		version = extractVersionFromString(
			banner,
			"Apache/",
		)

	case strings.Contains(bannerLower, "nginx"):
		service = "http"
		cpe = "cpe:/a:nginx:nginx"
		version = extractVersionFromString(
			banner,
			"nginx/",
		)

	case strings.Contains(bannerLower, "openssh"):
		service = "ssh"
		cpe = "cpe:/a:openbsd:openssh"
		version = extractVersionFromString(
			banner,
			"OpenSSH_",
		)

	default:
		service = "unknown"
	}

	return
}

func extractVersion(
	banner string,
	probes []string,
) string {

	for _, probe := range probes {

		idx := strings.Index(
			banner,
			probe,
		)

		if idx >= 0 {

			rest := banner[idx+len(probe):]

			rest = strings.TrimLeft(
				rest,
				" /:",
			)

			words := strings.Fields(rest)

			if len(words) > 0 {
				return probe + " " + words[0]
			}
		}
	}

	return ""
}

func extractVersionFromString(
	banner,
	prefix string,
) string {

	idx := strings.Index(
		banner,
		prefix,
	)

	if idx < 0 {
		return ""
	}

	rest := banner[idx+len(prefix):]

	end := strings.IndexAny(
		rest,
		" \r\n\t()",
	)

	if end > 0 {
		return rest[:end]
	}

	return rest
}

func udpProbe(port int) []byte {
	switch port {

	case 53:
		return []byte{
			0x00, 0x01, 0x01, 0x00,
			0x00, 0x01, 0x00, 0x00,
		}

	case 123:
		return []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		}

	default:
		return []byte("\r\n")
	}
}

func isCommonUDP(port int) bool {
	commonUDP := map[int]bool{
		53:   true,  // DNS
		67:   true,  // DHCP
		68:   true,  // DHCP
		69:   true,  // TFTP
		123:  true,  // NTP
		161:  true,  // SNMP
		162:  true,  // SNMP Trap
		500:  true,  // IPSec
		4500: true,  // IPSec NAT-T
		5353: true,  // mDNS
	}

	return commonUDP[port]
}

func sortPorts(ports []PortResult) {
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})
}

func removeDuplicatePorts(
	ports []PortResult,
) []PortResult {

	seen := make(map[string]bool)

	var result []PortResult

	for _, p := range ports {

		key := fmt.Sprintf(
			"%d-%s",
			p.Port,
			p.Protocol,
		)

		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result
}
