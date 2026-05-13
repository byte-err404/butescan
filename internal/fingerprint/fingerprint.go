package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"time"

	"butescan/internal/scanner"
)

// Fingerprinter handles OS detection
type Fingerprinter struct {
	host    string
	timeout time.Duration
}

// New creates a new Fingerprinter
func New(host string, timeout time.Duration) *Fingerprinter {
	return &Fingerprinter{
		host:    host,
		timeout: timeout,
	}
}

// Detect attempts to determine the OS from open ports and banners
func (f *Fingerprinter) Detect(ports []scanner.PortResult) string {

	// Method 1: Banner-based fingerprinting
	if os := f.detectFromBanners(ports); os != "" {
		return os
	}

	// Method 2: TTL-based fingerprinting
	if os := f.detectFromTTL(); os != "" {
		return os
	}

	// Method 3: Port heuristic fingerprinting
	if os := f.detectFromPorts(ports); os != "" {
		return os
	}

	return "Unknown"
}

// Banner-based OS detection
func (f *Fingerprinter) detectFromBanners(ports []scanner.PortResult) string {

	for _, p := range ports {

		banner := strings.ToLower(p.Banner)
		version := strings.ToLower(p.Version)

		combined := banner + " " + version

		switch {

		// Windows
		case strings.Contains(combined, "windows"),
			strings.Contains(combined, "microsoft"),
			strings.Contains(combined, "iis"),
			strings.Contains(combined, "win32"),
			strings.Contains(combined, "win64"):

			return detectWindowsVersion(combined)

		// Linux distros
		case strings.Contains(combined, "ubuntu"):
			return "Linux (Ubuntu)"

		case strings.Contains(combined, "debian"):
			return "Linux (Debian)"

		case strings.Contains(combined, "centos"):
			return "Linux (CentOS)"

		case strings.Contains(combined, "fedora"):
			return "Linux (Fedora)"

		case strings.Contains(combined, "red hat"),
			strings.Contains(combined, "rhel"):
			return "Linux (RedHat)"

		case strings.Contains(combined, "arch"):
			return "Linux (Arch)"

		case strings.Contains(combined, "alpine"):
			return "Linux (Alpine)"

		case strings.Contains(combined, "kali"):
			return "Linux (Kali)"

		case strings.Contains(combined, "linux"):
			return "Linux"

		// BSD/macOS
		case strings.Contains(combined, "darwin"),
			strings.Contains(combined, "macos"),
			strings.Contains(combined, "mac os"):
			return "macOS/Darwin"

		case strings.Contains(combined, "freebsd"):
			return "FreeBSD"

		case strings.Contains(combined, "openbsd"):
			return "OpenBSD"

		case strings.Contains(combined, "netbsd"):
			return "NetBSD"

		// Network devices
		case strings.Contains(combined, "cisco"):
			return "Cisco IOS"

		case strings.Contains(combined, "juniper"):
			return "Juniper JunOS"

		case strings.Contains(combined, "mikrotik"):
			return "MikroTik RouterOS"

		case strings.Contains(combined, "openwrt"):
			return "OpenWrt"

		case strings.Contains(combined, "dd-wrt"):
			return "DD-WRT"

		// Unix variants
		case strings.Contains(combined, "solaris"),
			strings.Contains(combined, "sunos"):
			return "Oracle Solaris"

		case strings.Contains(combined, "aix"):
			return "IBM AIX"
		}
	}

	return ""
}

// TTL fingerprinting
func (f *Fingerprinter) detectFromTTL() string {

	conn, err := net.DialTimeout(
		"ip4:icmp",
		f.host,
		f.timeout,
	)

	if err != nil {
		return ""
	}

	defer conn.Close()

	// ICMP Echo Request
	msg := make([]byte, 8)

	msg[0] = 8
	msg[1] = 0

	checksum := icmpChecksum(msg)

	msg[2] = byte(checksum >> 8)
	msg[3] = byte(checksum & 0xff)

	conn.SetDeadline(time.Now().Add(f.timeout))

	_, err = conn.Write(msg)
	if err != nil {
		return ""
	}

	reply := make([]byte, 1500)

	n, err := conn.Read(reply)
	if err != nil || n < 20 {
		return ""
	}

	ttl := int(reply[8])

	return ttlToOS(ttl)
}

// Port heuristic fingerprinting
func (f *Fingerprinter) detectFromPorts(
	ports []scanner.PortResult,
) string {

	portSet := make(map[int]bool)

	for _, p := range ports {
		portSet[p.Port] = true
	}

	// Windows
	if portSet[135] &&
		portSet[139] &&
		portSet[445] {

		if portSet[3389] {
			return "Windows Server (RDP Enabled)"
		}

		return "Windows"
	}

	// Linux
	if portSet[22] &&
		!portSet[445] &&
		!portSet[135] {

		if portSet[80] || portSet[443] {
			return "Linux Web Server"
		}

		return "Linux/Unix"
	}

	// Router / switch
	if portSet[23] &&
		portSet[22] &&
		!portSet[80] {

		return "Network Device"
	}

	// macOS guess
	if portSet[548] || portSet[5900] {
		return "macOS (Possible)"
	}

	// Kubernetes
	if portSet[6443] {
		return "Kubernetes Node"
	}

	// Docker / container
	if portSet[2375] || portSet[2376] {
		return "Docker Host"
	}

	return ""
}

// TTL mapping
func ttlToOS(ttl int) string {

	switch {

	case ttl >= 250:
		return "Cisco/Network Device"

	case ttl >= 120:
		return "Windows"

	case ttl >= 60:
		return "Linux/Unix"

	case ttl >= 50:
		return "macOS/BSD"

	default:
		return fmt.Sprintf("Unknown (TTL=%d)", ttl)
	}
}

// Windows version detection
func detectWindowsVersion(banner string) string {

	switch {

	case strings.Contains(banner, "windows server 2022"):
		return "Windows Server 2022"

	case strings.Contains(banner, "windows server 2019"):
		return "Windows Server 2019"

	case strings.Contains(banner, "windows server 2016"):
		return "Windows Server 2016"

	case strings.Contains(banner, "windows server 2012"):
		return "Windows Server 2012"

	case strings.Contains(banner, "windows 11"):
		return "Windows 11"

	case strings.Contains(banner, "windows 10"):
		return "Windows 10"

	case strings.Contains(banner, "windows 8"):
		return "Windows 8"

	case strings.Contains(banner, "windows 7"):
		return "Windows 7"

	default:
		return "Windows"
	}
}

// ICMP checksum
func icmpChecksum(data []byte) uint16 {

	var sum uint32

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return uint16(^sum)
}
