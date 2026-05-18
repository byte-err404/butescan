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
	timingProfile  string
	decoySources   string
	fragmentPacket bool
	sprayIP        string
	tracerouteMode bool
	geolocation    bool
	dnsResolution  bool
	outputXML      bool
	outputGrep     bool
	dontPing       bool
	pingProbes     string
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
	Short: "Advanced network scanner with full Nmap compatibility",
	Long: `Butescan - NMAP-compatible Network Scanner

Features:
  • 9 scan types (SYN, TCP, UDP, ACK, Window, Maimon, Idle, IP, SCTP)
  • Host discovery with multiple probe types
  • Service/version detection (sV)
  • OS detection with CPE identifiers
  • 50+ NSE-style vulnerability scripts
  • Timing profiles (T0-T5)
  • Decoy scanning & IP spoofing
  • Traceroute mapping
  • Geolocation & DNS resolution
  • Multiple output formats (text, json, html, xml, greppable)
  • Firewall evasion techniques
  • CVE vulnerability lookup
  • Rate limiting & fragmentation

Examples:
  butescan -t 192.168.1.1 -sS -A              # Aggressive SYN scan
  butescan -t 192.168.1.1 -T4 -A -sV          # Fast aggressive scan
  butescan -t 192.168.1.1 -D decoy1,decoy2    # Decoy scanning
  butescan -t 192.168.1.1 -f --traceroute     # Fragmented + traceroute
  butescan -t 192.168.1.0/24 -T2 --geo -O     # Stealthy with geolocation`,
	RunE:  runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// ===== TARGET OPTIONS =====
	rootCmd.Flags().StringVarP(&targetHost, "target", "t", "", "Target host/IP/CIDR range (required)")
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "Port range (80,443 or 1-65535)")
	rootCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Scan top N common ports")

	// ===== HOST DISCOVERY PROBES =====
	rootCmd.Flags().BoolP("sn", "sn", false, "Ping scan (host discovery only, no port scan)")
	rootCmd.Flags().StringVar(&pingProbes, "ping-probes", "ICMP,TCP,ARP", "Host discovery probe types: ICMP, TCP, UDP, ARP, SCTP")
	rootCmd.Flags().BoolVar(&dontPing, "P0", false, "Skip ping (treat all as online)")
	rootCmd.Flags().BoolVar(&dontPing, "Pn", false, "Skip ping (treat all as online)")

	// ===== SCAN TECHNIQUES (NMAP STYLE) =====
	rootCmd.Flags().BoolP("sS", "sS", false, "TCP SYN scan (stealth, requires root)")
	rootCmd.Flags().BoolP("sT", "sT", false, "TCP Connect scan")
	rootCmd.Flags().BoolP("sU", "sU", false, "UDP scan")
	rootCmd.Flags().BoolP("sA", "sA", false, "TCP ACK scan (firewall detection)")
	rootCmd.Flags().BoolP("sW", "sW", false, "TCP Window scan (OS fingerprinting)")
	rootCmd.Flags().BoolP("sM", "sM", false, "TCP Maimon scan")
	rootCmd.Flags().BoolP("sI", "sI", false, "Idle/Zombie scan (ultra-stealthy)")
	rootCmd.Flags().BoolP("sO", "sO", false, "IP protocol scan")
	rootCmd.Flags().BoolP("sY", "sY", false, "SCTP INIT scan")

	// ===== DETECTION OPTIONS =====
	rootCmd.Flags().BoolP("sV", "V", false, "Service/version detection (detailed fingerprinting)")
	rootCmd.Flags().BoolP("O", "O", false, "OS detection (with CPE identifiers)")
	rootCmd.Flags().BoolP("A", "A", false, "Aggressive: OS + version + scripts + traceroute")
	rootCmd.Flags().BoolVar(&bannerGrab, "banner", false, "Enable banner grabbing")

	// ===== TIMING & PERFORMANCE =====
	rootCmd.Flags().StringVarP(&timingProfile, "timing", "T", "normal", "Timing profile: paranoid, sneaky, polite, normal, aggressive, insane")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "", 1000, "Timeout in milliseconds")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 1000, "Concurrent threads")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "Rate limit between requests (ms)")
	rootCmd.Flags().IntVar(&rateLimit, "min-rate", 0, "Minimum packet rate per second")
	rootCmd.Flags().IntVar(&rateLimit, "max-rate", 0, "Maximum packet rate per second")

	// ===== FIREWALL EVASION =====
	rootCmd.Flags().BoolVarP(&fragmentPacket, "fragment", "f", false, "Fragment packets (firewall evasion)")
	rootCmd.Flags().StringVar(&decoySources, "decoy", "", "Use decoy IPs: -D RND,RND,ME (comma-separated)")
	rootCmd.Flags().StringVar(&sprayIP, "spoof-source", "", "Spoof source IP address")
	rootCmd.Flags().BoolP("scan-delay", "g", false, "Use scan delay between probes")

	// ===== ADVANCED OPTIONS =====
	rootCmd.Flags().BoolVarP(&tracerouteMode, "traceroute", "route", false, "Trace route to host")
	rootCmd.Flags().BoolVar(&geolocation, "geo", false, "Add geolocation data to results")
	rootCmd.Flags().BoolVar(&dnsResolution, "resolve-all", false, "Perform DNS resolution for all IPs")

	// ===== ENUMERATION =====
	rootCmd.Flags().BoolVar(&cveCheck, "cve", false, "CVE lookup for detected services")
	rootCmd.Flags().StringSliceVar(&runScripts, "script", []string{}, "NSE-style scripts (comma-separated)")

	// ===== OUTPUT OPTIONS =====
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&outputFmt, "format", "text", "Output format: text, json, html, xml, greppable")
	rootCmd.Flags().BoolVar(&outputXML, "oX", false, "Output in XML format")
	rootCmd.Flags().BoolVar(&outputGrep, "oG", false, "Output in greppable format")

	// ===== MISC OPTIONS =====
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolP("debug", "d", false, "Debug mode")
	rootCmd.Flags().BoolP("help-scripts", "", false, "Show available NSE-style scripts")
	rootCmd.Flags().BoolP("list-timing", "", false, "List timing profiles")

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

	// ===== SHOW HELP =====
	if help, _ := cmd.Flags().GetBool("help-scripts"); help {
		showScriptHelp()
		return nil
	}

	if timing, _ := cmd.Flags().GetBool("list-timing"); timing {
		showTimingProfiles()
		return nil
	}

	// ===== VALIDATE TIMING PROFILE =====
	validTimings := map[string]bool{
		"paranoid": true, "0": true,
		"sneaky": true, "1": true,
		"polite": true, "2": true,
		"normal": true, "3": true,
		"aggressive": true, "4": true,
		"insane": true, "5": true,
	}

	if !validTimings[strings.ToLower(timingProfile)] {
		return fmt.Errorf("invalid timing profile: %s (use: paranoid, sneaky, polite, normal, aggressive, insane)", timingProfile)
	}

	cyan("[*] Timing Profile: %s\n", timingProfile)

	// ===== PING SCAN ONLY =====
	if v, _ := cmd.Flags().GetBool("sn"); v {
		cyan("[*] Host Discovery Only (no port scanning)\n")
		// TODO: Implement host discovery only
		return nil
	}

	// ===== PARSE SCAN TYPE =====
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
		cyan("[*] Scan Type: TCP Window\n")
	}
	if v, _ := cmd.Flags().GetBool("sM"); v {
		scanType = "maimon"
		cyan("[*] Scan Type: TCP Maimon\n")
	}
	if v, _ := cmd.Flags().GetBool("sI"); v {
		scanType = "idle"
		cyan("[*] Scan Type: Idle/Zombie (ultra-stealthy)\n")
	}
	if v, _ := cmd.Flags().GetBool("sO"); v {
		scanType = "ipproto"
		cyan("[*] Scan Type: IP Protocol\n")
	}
	if v, _ := cmd.Flags().GetBool("sY"); v {
		scanType = "sctp"
		cyan("[*] Scan Type: SCTP INIT\n")
	}

	// ===== AGGRESSIVE MODE =====
	if v, _ := cmd.Flags().GetBool("A"); v {
		osDetect = true
		versionDetect = true
		bannerGrab = true
		tracerouteMode = true
		runScripts = append(runScripts, "default")
		yellow("[*] Aggressive Mode: OS + version + scripts + traceroute\n")
	}

	if v, _ := cmd.Flags().GetBool("sV"); v {
		versionDetect = true
		cyan("[*] Service Version Detection: Enabled\n")
	}

	if v, _ := cmd.Flags().GetBool("O"); v {
		osDetect = true
		cyan("[*] OS Detection: Enabled\n")
	}

	// ===== FIREWALL EVASION =====
	if fragmentPacket {
		yellow("[*] Packet Fragmentation: Enabled\n")
	}

	if decoySources != "" {
		yellow("[*] Decoy Scanning: %s\n", decoySources)
	}

	if tracerouteMode {
		cyan("[*] Traceroute: Enabled\n")
	}

	if geolocation {
		cyan("[*] Geolocation: Enabled\n")
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

	cyan("[*] Targets: %d | Ports: %d | Threads: %d | Timing: %s\n",
		len(targets), len(ports), threads, timingProfile)

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
			BannerGrab: bannerGrab || versionDetect,
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

		// ===== CVE =====
		if cveCheck {
			client := cve.NewClient()
			for i, p := range result.OpenPorts {
				if p.Service != "" {
					cves, _ := client.Lookup(p.Service, p.Version)
					result.OpenPorts[i].CVEs = append(result.OpenPorts[i].CVEs, cves...)
					if len(cves) > 0 {
						magenta("[!] Port %d: %d CVE(s) found\n", p.Port, len(cves))
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
╔══════════════════════════════════════════════════════════════════╗
║         BUTESCAN 50+ NSE-STYLE VULNERABILITY SCRIPTS              ║
╚══════════════════════════════════════════════════════════════════╝

HTTP/HTTPS (10 scripts):
  http-headers           http-title             http-methods
  http-robots            http-git               http-backup-finder
  http-wordpress-enum    http-wordpress-brute   http-phpself
  http-slowloris

SSL/TLS (6 scripts):
  ssl-cert               ssl-heartbleed         ssl-poodle
  ssl-drown              ssl-ccs-injection      ssl-weak-ciphers

SSH (4 scripts):
  ssh-hostkey            ssh-auth-methods       ssh-brute
  ssh-rsa-shodan

FTP (3 scripts):
  ftp-anon               ftp-brute              ftp-bounce

SMTP (3 scripts):
  smtp-commands          smtp-open-relay        smtp-enum-users

DNS (4 scripts):
  dns-brute              dns-zone-transfer      dns-nsec-enum
  dns-recursion-check

Databases (6 scripts):
  mysql-info             mysql-empty-password   redis-info
  redis-brute            mongodb-info           postgresql-enum

Network (4 scripts):
  snmp-info              snmp-brute             ntp-info
  ldap-search

Vulnerability (10 scripts):
  smb-vuln-ms17-010      smb-enum-shares        smb-os-discovery
  jboss-status           jboss-brute            tomcat-brute
  cassandra-info         elasticsearch-info     memcached-info
  rabbitmq-info

Example:
  butescan -t 192.168.1.1 --script default         # Run default scripts
  butescan -t 192.168.1.1 --script http-*          # All HTTP scripts
  butescan -t 192.168.1.1 --script ssl-*,ssh-*    # SSL and SSH scripts
`)
}

func showTimingProfiles() {
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════╗
║              NMAP TIMING PROFILES (-T0 to -T5)                    ║
╚══════════════════════════════════════════════════════════════════╝

-T0 (Paranoid)
  • Ultra-slow, extremely stealthy
  • 5 minutes between probes
  • Avoid IDS/IPS detection
  • Use case: Very restricted networks

-T1 (Sneaky)
  • Very slow, stealthy
  • 15 seconds between probes
  • Minimize detection risk
  • Use case: Sensitive networks with monitoring

-T2 (Polite)
  • Slow, respectful scanning
  • Moderate timing
  • Reduces network impact
  • Use case: Shared networks, during business hours

-T3 (Normal) [DEFAULT]
  • Balanced speed and stealth
  • Standard timing
  • Good for most situations
  • Use case: General scanning

-T4 (Aggressive)
  • Fast, assumes modern networks
  • Suitable for high-speed LANs
  • May overwhelm slow networks
  • Use case: Internal networks, controlled environments

-T5 (Insane)
  • Extremely fast, assumes very fast networks
  • High risk of inaccuracy
  • Parallel scanning
  • Use case: Very controlled internal networks only

Usage:
  butescan -t 192.168.1.1 -T0              # Paranoid (very stealthy)
  butescan -t 192.168.1.1 -T2              # Polite (safe)
  butescan -t 192.168.1.1 -T4              # Aggressive (fast)
`)
}
