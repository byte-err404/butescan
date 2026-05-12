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
	return &Fingerprinter{host: host, timeout: timeout}
}

// Detect attempts to determine the OS from open ports and banners
func (f *Fingerprinter) Detect(ports []scanner.PortResult) string {
	// Method 1: Banner-based detection
	if os := f.detectFromBanners(ports); os != "" {
		return os
	}

	// Method 2: TTL-based detection
	if os := f.detectFromTTL(); os != "" {
		return os
	}

	// Method 3: Port combination heuristic
	if os := f.detectFromPorts(ports); os != "" {
		return os
	}

	return ""
}

// detectFromBanners looks at service banners for OS hints
func (f *Fingerprinter) detectFromBanners(ports []scanner.PortResult) string {
	for _, p := range ports {
		banner := strings.ToLower(p.Banner)
		version := strings.ToLower(p.Version)
		combined := banner + " " + version

		switch {
		// Windows indicators
		case strings.Contains(combined, "windows") ||
			strings.Contains(combined, "microsoft") ||
			strings.Contains(combined, "iis") ||
			strings.Contains(combined, "win32") ||
			strings.Contains(combined, "win64"):
			return detectWindowsVersion(combined)

		// Linux indicators
		case strings.Contains(combined, "ubuntu"):
			return "Linux (Ubuntu)"
		case strings.Contains(combined, "debian"):
			return "Linux (Debian)"
		case strings.Contains(combined, "centos"):
			return "Linux (CentOS)"
		case strings.Contains(combined, "fedora"):
			return "Linux (Fedora)"
		case strings.Contains(combined, "red hat") || strings.Contains(combined, "rhel"):
			return "Linux (Red Hat)"
		case strings.Contains(combined, "arch"):
			return "Linux (Arch)"
		case strings.Contains(combined, "linux"):
			return "Linux"

		// macOS indicators
		case strings.Contains(combined, "darwin") || strings.Contains(combined, "macos") ||
			strings.Contains(combined, "mac os"):
			return "macOS/Darwin"

		// FreeBSD/NetBSD/OpenBSD
		case strings.Contains(combined, "freebsd"):
			return "FreeBSD"
		case strings.Contains(combined, "netbsd"):
			return "NetBSD"
		case strings.Contains(combined, "openbsd"):
			return "OpenBSD"

		// Embedded/Network devices
		case strings.Contains(combined, "cisco"):
			return "Cisco IOS"
		case strings.Contains(combined, "juniper"):
			return "Juniper Junos"
		case strings.Contains(combined, "mikrotik"):
			return "MikroTik RouterOS"
		case strings.Contains(combined, "dd-wrt"):
			return "DD-WRT (Linux)"
		case strings.Contains(combined, "openwrt"):
			return "OpenWrt (Linux)"
		case strings.Contains(combined, "aix"):
			return "IBM AIX"
		case strings.Contains(combined, "solaris") || strings.Contains(combined, "sunos"):
			return "Oracle Solaris"
		}
	}
	return ""
}

// detectFromTTL tries TCP connection timing to guess OS
func (f *Fingerprinter) detectFromTTL() string {
	// Send a crafted packet and analyze response timing patterns
	// This is a simplified TTL detection using ICMP echo

	conn, err := net.DialTimeout("ip4:icmp", f.host, f.timeout)
	if err != nil {
		// Can't use raw sockets, try alternative
		return f.detectFromTCPBehavior()
	}
	defer conn.Close()

	// Build ICMP echo request
	msg := make([]byte, 8)
	msg[0] = 8  // ICMP Echo Request
	msg[1] = 0  // Code
	msg[2] = 0  // Checksum high
	msg[3] = 0  // Checksum low
	msg[4] = 0  // ID high
	msg[5] = 1  // ID low
	msg[6] = 0  // Seq high
	msg[7] = 1  // Seq low

	// Calculate checksum
	checksum := icmpChecksum(msg)
	msg[2] = byte(checksum >> 8)
	msg[3] = byte(checksum & 0xff)

	conn.SetDeadline(time.Now().Add(f.timeout))
	conn.Write(msg)

	reply := make([]byte, 28)
	n, err := conn.Read(reply)
	if err != nil || n < 20 {
		return ""
	}

	// Extract TTL from IP header (byte 8 of IP header)
	ttl := int(reply[8])

	return ttlToOS(ttl)
}

func (f *Fingerprinter) detectFromTCPBehavior() string {
	// Connect and measure window size, options etc
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", f.host), f.timeout)
	if err != nil {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", f.host), f.timeout)
		if err != nil {
			return ""
		}
	}
	defer conn.Close()

	// Simple heuristic: Windows tends to have window size 65535
	// This is very basic and not reliable
	return ""
}

// detectFromPorts uses port combination heuristics
func (f *Fingerprinter) detectFromPorts(ports []scanner.PortResult) string {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p.Port] = true
	}

	// Windows Server indicators
	if portSet[135] && portSet[139] && portSet[445] {
		if portSet[3389] {
			return "Windows Server (RDP enabled)"
		}
		return "Windows"
	}

	// Windows with RDP only
	if portSet[3389] && portSet[445] {
		return "Windows (RDP + SMB)"
	}

	// Linux indicators
	if portSet[22] && !portSet[135] && !portSet[445] {
		if portSet[80] || portSet[443] {
			return "Linux (Web Server)"
		}
		return "Linux/Unix"
	}

	// Network device
	if portSet[23] && portSet[22] && !portSet[80] {
		return "Network Device (Router/Switch)"
	}

	// macOS
	if portSet[548] || portSet[5900] { // AFP or VNC
		return "macOS (possible)"
	}

	return "Unknown"
}

// ttlToOS maps TTL values to likely OS
func ttlToOS(ttl int) string {
	switch {
	case ttl <= 64 && ttl > 56:
		return "Linux/Unix (TTL ~64)"
	case ttl <= 128 && ttl > 120:
		return "Windows (TTL ~128)"
	case ttl <= 255 && ttl > 248:
		return "Cisco/Network Device (TTL ~255)"
	case ttl <= 56 && ttl > 48:
		return "macOS/BSD (TTL ~64 with hops)"
	default:
		return fmt.Sprintf("Unknown OS (TTL=%d)", ttl)
	}
}

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
	case strings.Contains(banner, "windows 7"):
		return "Windows 7"
	default:
		return "Windows"
	}
}

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
