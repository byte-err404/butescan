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

		pr.Service, pr.Version = detectService(
			port,
			banner,
		)
	} else {
		pr.Service, pr.Version = detectService(port, "")
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

		pr.Service, pr.Version = detectService(
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

		pr.Service, _ = detectService(port, "")

		return pr, true
	}

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
	probes  []string
}

var serviceDB = map[int]serviceFingerprint{
	21:    {service: "ftp", probes: []string{"220", "FTP", "ProFTPD", "vsftpd"}},
	22:    {service: "ssh", probes: []string{"SSH", "OpenSSH"}},
	23:    {service: "telnet", probes: []string{"Telnet"}},
	25:    {service: "smtp", probes: []string{"SMTP", "Postfix"}},
	53:    {service: "dns"},
	80:    {service: "http", probes: []string{"HTTP", "Apache", "nginx"}},
	110:   {service: "pop3"},
	143:   {service: "imap"},
	443:   {service: "https", probes: []string{"HTTP", "HTTPS", "Apache", "nginx"}},
	445:   {service: "microsoft-ds"},
	3306:  {service: "mysql", probes: []string{"MySQL", "MariaDB"}},
	5432:  {service: "postgresql", probes: []string{"PostgreSQL"}},
	6379:  {service: "redis", probes: []string{"redis_version"}},
	8080:  {service: "http-proxy"},
	8443:  {service: "https-alt"},
	9200:  {service: "elasticsearch"},
	27017: {service: "mongodb"},
}

// detectService identifies services
func detectService(port int, banner string) (
	service,
	version string,
) {

	if fp, ok := serviceDB[port]; ok {

		service = fp.service

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
		version = extractVersionFromString(
			banner,
			"Apache/",
		)

	case strings.Contains(bannerLower, "nginx"):
		service = "http"
		version = extractVersionFromString(
			banner,
			"nginx/",
		)

	case strings.Contains(bannerLower, "openssh"):
		service = "ssh"
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

	default:
		return []byte("\r\n")
	}
}

func isCommonUDP(port int) bool {
	commonUDP := map[int]bool{
		53:   true,
		67:   true,
		68:   true,
		69:   true,
		123:  true,
		161:  true,
		162:  true,
		500:  true,
		4500: true,
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
