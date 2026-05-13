package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"butescan/internal/cve"
	"butescan/internal/fingerprint"
	"butescan/internal/report"
	"butescan/internal/scanner"
	"butescan/internal/scripts"
)

var (
	targetHost     string
	portRange      string
	timeout        int
	threads        int
	scanType       string
	outputFile     string
	outputFmt      string
	runScripts     []string
	cveCheck       bool
	osDetect       bool
	bannerGrab     bool
	topPorts       int
	verbose        bool
	versionDetect  bool
	aggressiveMode bool
	skipPing       bool
	rateLimit      int
)

var banner = `
 ██████╗ ██╗   ██╗████████╗███████╗
 ██╔══██╗██║   ██║╚══██╔══╝██╔════╝
 ██████╔╝██║   ██║   ██║   █████╗
 ██╔══██╗██║   ██║   ██║   ██╔══╝
 ██████╔╝╚██████╔╝   ██║   ███████╗
 ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
`

var rootCmd = &cobra.Command{
	Use:   "butescan -t <target> [flags]",
	Short: "Advanced network scanner with nmap-style scanning",
	Long: `Butescan is a fast, feature-rich network scanner combining RustScan speed with Nmap-inspired detection.

Examples:
  butescan -t 192.168.1.1 -sS                    # TCP SYN scan
  butescan -t 192.168.1.1 -sU -p 53,161          # UDP scan
  butescan -t 192.168.1.1 -A                     # Aggressive scan (OS + version + scripts)
  butescan -t 192.168.1.0/24 --top-ports 100     # Scan subnet
  butescan -t 192.168.1.1 -p 1-65535 --cve       # Full port scan with CVE lookup`,
	RunE:  runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// ===== TARGET OPTIONS =====
	rootCmd.Flags().StringVarP(&targetHost, "target", "t", "", "Target host/IP/CIDR range (required)")
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "Port range (e.g., 80,443 or 1-65535)")
	rootCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Scan top N common ports (e.g., 100, 1000)")

	// ===== SCAN TECHNIQUES (NMAP STYLE) =====
	rootCmd.Flags().BoolP("sS", "sS", false, "TCP SYN scan (stealth scan, requires root)")
	rootCmd.Flags().BoolP("sT", "sT", false, "TCP Connect scan (uses OS connection API)")
	rootCmd.Flags().BoolP("sU", "sU", false, "UDP scan")
	rootCmd.Flags().BoolP("sA", "sA", false, "TCP ACK scan (firewall testing)")
	rootCmd.Flags().BoolP("sW", "sW", false, "TCP Window scan (OS fingerprinting)")
	rootCmd.Flags().BoolP("sM", "sM", false, "TCP Maimon scan")
	rootCmd.Flags().BoolP("sI", "sI", false, "Idle/Zombie scan (slow, requires idle host)")
	rootCmd.Flags().BoolP("sO", "sO", false, "IP protocol scan")
	rootCmd.Flags().BoolP("Pn", "Pn", false, "Treat all hosts as online (skip ping)")

	// ===== DETECTION OPTIONS =====
	rootCmd.Flags().BoolP("sV", "V", false, "Service/version detection")
	rootCmd.Flags().BoolP("O", "O", false, "OS detection (passive fingerprinting)")
	rootCmd.Flags().BoolP("A", "A", false, "Aggressive scan (OS + version + scripts)")
	rootCmd.Flags().BoolVar(&bannerGrab, "banner", false, "Enable banner grabbing")

	// ===== ENUMERATION =====
	rootCmd.Flags().BoolVar(&cveCheck, "cve", false, "CVE lookup for detected services (requires NVD API)")
	rootCmd.Flags().StringSliceVar(&runScripts, "script", []string{}, "Comma-separated NSE-style scripts to run")

	// ===== PERFORMANCE OPTIONS =====
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 1000, "Connection timeout in milliseconds")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 1000, "Number of concurrent threads")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "Rate limit between requests (ms)")

	// ===== OUTPUT OPTIONS =====
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&outputFmt, "format", "text", "Output format: text, json, html")

	// ===== MISC OPTIONS =====
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolP("help-scripts", "h", false, "Show available NSE-style scripts")
	rootCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Colors
	green := color.New(color.FgGreen).PrintfFunc()
	red := color.New(color.FgRed).PrintfFunc()
	yellow := color.New(color.FgYellow).PrintfFunc()
	cyan := color.New(color.FgCyan).PrintfFunc()
	magenta := color.New(color.FgMagenta).PrintfFunc()

	fmt.Println(banner)

	// ===== HELP FOR SCRIPTS =====
	if help, _ := cmd.Flags().GetBool("help-scripts"); help {
		showScriptHelp()
		return nil
	}

	// ===== PARSE SCAN TYPE FROM FLAGS =====
	scanType = "tcp" // default

	if v, _ := cmd.Flags().GetBool("sS"); v {
		scanType = "syn"
		cyan("[*] Scan Type: TCP SYN (stealth)\n")
	}
	if v, _ := cmd.Flags().GetBool("sT"); v {
		scanType = "tcp"
		cyan("[*] Scan Type: TCP Connect\n")
	}
	if v, _ := cmd.Flags().GetBool("sU"); v {
		scanType = "udp"
		cyan("[*] Scan Type: UDP\n")
	}
	if v, _ := cmd.Flags().GetBool("sA"); v {
		scanType = "ack"
		cyan("[*] Scan Type: TCP ACK (firewall detection)\n")
	}
	if v, _ := cmd.Flags().GetBool("sW"); v {
		scanType = "window"
		cyan("[*] Scan Type: TCP Window (OS fingerprinting)\n")
	}
	if v, _ := cmd.Flags().GetBool("sM"); v {
		scanType = "maimon"
		cyan("[*] Scan Type: TCP Maimon\n")
	}
	if v, _ := cmd.Flags().GetBool("sI"); v {
		scanType = "idle"
		cyan("[*] Scan Type: Idle/Zombie (requires idle host)\n")
	}
	if v, _ := cmd.Flags().GetBool("sO"); v {
		scanType = "ipproto"
		cyan("[*] Scan Type: IP Protocol\n")
	}
	if v, _ := cmd.Flags().GetBool("Pn"); v {
		skipPing = true
		cyan("[*] Host Discovery: DISABLED (treating all hosts as online)\n")
	}

	// ===== FLAGS LOGIC (AGGRESSIVE MODE, DETECTION, ETC) =====
	if v, _ := cmd.Flags().GetBool("A"); v {
		osDetect = true
		versionDetect = true
		bannerGrab = true
		runScripts = append(runScripts, "http-headers", "ssh-hostkey")
		yellow("[*] Aggressive Mode: Enabled (OS detection, version detection, scripts)\n")
	}

	if v, _ := cmd.Flags().GetBool("sV"); v {
		versionDetect = true
		cyan("[*] Service Detection: Enabled\n")
	}

	if v, _ := cmd.Flags().GetBool("O"); v {
		osDetect = true
		cyan("[*] OS Detection: Enabled\n")
	}

	if bannerGrab {
		cyan("[*] Banner Grabbing: Enabled\n")
	}

	if cveCheck {
		cyan("[*] CVE Lookup: Enabled\n")
	}

	// ===== TARGETS =====
	targets, err := resolveTargets(targetHost)
	if err != nil {
		return err
	}

	ports, err := parsePorts(portRange, topPorts)
	if err != nil {
		return err
	}

	start := time.Now()

	cyan("[*] Targets: %d | Ports: %d | Threads: %d | Timeout: %dms\n",
		len(targets), len(ports), threads, timeout)

	var allResults []*scanner.ScanResult

	// ===== SCAN LOOP =====
	for _, target := range targets {
		yellow("[>] Scanning %s ...\n", target)

		cfg := &scanner.Config{
			Host:       target,
			Ports:      ports,
			Timeout:    time.Duration(timeout) * time.Millisecond,
			Threads:    threads,
			ScanType:   scanType,
			BannerGrab: bannerGrab,
			Verbose:    verbose,
			RateLimit:  time.Duration(rateLimit) * time.Millisecond,
		}

		s := scanner.New(cfg)
		result, err := s.Scan()
		if err != nil {
			red("[ERROR] %v\n", err)
			continue
		}

		// ===== OS DETECT =====
		if osDetect {
			fp := fingerprint.New(target, time.Duration(timeout)*time.Millisecond)
			result.OS = fp.Detect(result.OpenPorts)
			if result.OS != "" {
				green("[+] OS Detected: %s\n", result.OS)
			}
		}

		// ===== SERVICE/VERSION DETECTION =====
		if versionDetect {
			for i, p := range result.OpenPorts {
				if p.Service != "" && p.Version == "" {
					result.OpenPorts[i].Version = detectServiceVersion(p.Banner)
				}
			}
		}

		// ===== CVE =====
		if cveCheck {
			client := cve.NewClient()
			for i, p := range result.OpenPorts {
				if p.Service != "" {
					cves, _ := client.Lookup(p.Service, p.Version)
					result.OpenPorts[i].CVEs = append(result.OpenPorts[i].CVEs, cves...)
					if len(cves) > 0 {
						magenta("[!] Port %d/%s: %d CVE(s) found\n", p.Port, p.Protocol, len(cves))
					}
				}
			}
		}

		// ===== SCRIPTS =====
		if len(runScripts) > 0 {
			engine := scripts.New()

			for _, sname := range runScripts {
				for i, p := range result.OpenPorts {
					out, _ := engine.Run(sname, target, p.Port, p.Service)
					if out != "" {
						result.OpenPorts[i].ScriptOutput =
							append(result.OpenPorts[i].ScriptOutput, out)
					}
				}
			}
		}

		printResults(result)

		allResults = append(allResults, result)
	}

	elapsed := time.Since(start)
	green("\n[✓] Scan completed in %s\n", elapsed)

	// ===== REPORT =====
	if outputFile != "" {
		rep := report.New(outputFmt)
		rep.Save(allResults, outputFile)
		green("[✓] Report saved to: %s\n", outputFile)
	}

	return nil
}

func showScriptHelp() {
	fmt.Println(`
╔════════════════════════════════════════════════════════════════╗
║           BUTESCAN NSE-STYLE SCRIPTS REFERENCE                 ║
╚════════════════════════════════════════════════════════════════╝

HTTP/HTTPS SCRIPTS:
  http-headers         - Dump all HTTP response headers
  http-title           - Extract page title from HTTP response
  http-methods         - Find dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT)
  http-robots          - Read robots.txt for hidden paths and directories
  ssl-cert             - Extract TLS certificate info and check expiry
  ssl-heartbleed       - Check for CVE-2014-0160 (OpenSSL Heartbleed)

SSH SCRIPTS:
  ssh-hostkey          - Retrieve SSH banner, host keys, and key types
  ssh-auth-methods     - Enumerate SSH authentication methods

FTP SCRIPTS:
  ftp-anon             - Test anonymous FTP login access

SMTP SCRIPTS:
  smtp-commands        - Enumerate SMTP EHLO commands and extensions
  smtp-open-relay      - Test for open mail relay vulnerability

DATABASE SCRIPTS:
  mysql-info           - Extract MySQL version from handshake
  redis-info           - Retrieve Redis INFO (unauthenticated check)
  redis-unauth         - Test unauthenticated Redis access
  mongodb-info         - Extract MongoDB version and access info

NETWORK SCRIPTS:
  dns-brute            - DNS subdomain enumeration via brute-force
  snmp-info            - Test SNMP public community string
  vnc-info             - Extract VNC version and authentication type
  telnet-ntlm-info     - Grab Telnet banner (protocol insecurity check)

USAGE EXAMPLES:
  butescan -t 192.168.1.1 --script http-headers,ssl-cert
  butescan -t 192.168.1.1 -p 80,443 --script http-headers,http-title,ssl-cert
  butescan -t 192.168.1.1 -p 22 --script ssh-hostkey,ssh-auth-methods
  butescan -t 192.168.1.1 -A --script http-headers,ssh-hostkey,ssl-cert

RUNNING ALL HTTP SCRIPTS:
  butescan -t 192.168.1.1 -p 80,443 --script http-headers,http-title,http-methods,http-robots,ssl-cert,ssl-heartbleed
`)
}

func detectServiceVersion(banner string) string {
	// Extract version from banner
	if strings.Contains(banner, "Apache/") {
		parts := strings.Split(banner, "Apache/")
		if len(parts) > 1 {
			version := strings.Fields(parts[1])[0]
			return "Apache " + version
		}
	}
	if strings.Contains(banner, "nginx/") {
		parts := strings.Split(banner, "nginx/")
		if len(parts) > 1 {
			version := strings.Fields(parts[1])[0]
			return "nginx " + version
		}
	}
	if strings.Contains(banner, "OpenSSH_") {
		parts := strings.Split(banner, "OpenSSH_")
		if len(parts) > 1 {
			version := strings.Fields(parts[1])[0]
			return "OpenSSH " + version
		}
	}
	return ""
}
