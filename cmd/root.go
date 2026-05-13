package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/fatih/color"

	"butescan/internal/cve"
	"butescan/internal/fingerprint"
	"butescan/internal/report"
	"butescan/internal/scanner"
	"butescan/internal/scripts"
)

var (
	targetHost  string
	portRange   string
	timeout     int
	threads     int
	scanType    string
	outputFile  string
	outputFmt   string
	runScripts  []string
	cveCheck    bool
	osDetect    bool
	bannerGrab  bool
	udpScan     bool
	topPorts    int
	verbose     bool
)

var banner = `
 ██████╗ ██╗   ██╗████████╗███████╗
 ██╔══██╗██║   ██║╚══██╔══╝██╔════╝
 ██████╔╝██║   ██║   ██║   █████╗
 ██╔══██╗██║   ██║   ██║   ██╔══╝
 ██████╔╝╚██████╔╝   ██║   ███████╗
 ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

      Advanced Network Recon Tool
      High-Speed • Modular • Stealth

      Author: byte-err404
      GitHub: https://github.com/byte-err404
`

var rootCmd = &cobra.Command{
	Use:   "butescan -t <target>",
	Short: "Fast and advanced network reconnaissance tool",
	Long: `A high-performance network scanning tool for security analysis:

  • TCP/UDP Port Scanning
  • Service & Version Detection
  • Vulnerability Enumeration
  • Banner Grabbing
  • OS Fingerprinting
  • Script Engine Support
  • JSON / HTML / Text Reporting`,
	RunE: runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&targetHost, "target", "t", "", "Target host/IP or CIDR range (required)")
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "Port range (e.g. 80,443 or 1-65535 or top)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 1000, "Timeout in milliseconds")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 1000, "Concurrent threads")
	rootCmd.Flags().StringVarP(&scanType, "scan-type", "s", "tcp", "Scan type: tcp, syn, udp, all")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&outputFmt, "format", "text", "Output format: text, json, html")
	rootCmd.Flags().StringSliceVar(&runScripts, "script", []string{}, "Scripts to run (e.g. http-headers,ssh-info)")
	rootCmd.Flags().BoolVar(&cveCheck, "cve", false, "Check CVEs for detected services")
	rootCmd.Flags().BoolVar(&osDetect, "os", false, "Enable OS detection")
	rootCmd.Flags().BoolVar(&bannerGrab, "banner", true, "Enable banner grabbing")
	rootCmd.Flags().BoolVar(&udpScan, "udp", false, "Include UDP scan")
	rootCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Scan top N common ports")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Println(color.CyanString(banner))

	// Resolve targets
	targets, err := resolveTargets(targetHost)
	if err != nil {
		red.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	// Parse ports
	ports, err := parsePorts(portRange, topPorts)
	if err != nil {
		red.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	startTime := time.Now()

	bold.Printf("\n[*] Starting Butescan at %s\n", startTime.Format("2006-01-02 15:04:05"))
	cyan.Printf("[*] Targets: %d host(s) | Ports: %d | Threads: %d | Timeout: %dms\n\n",
		len(targets), len(ports), threads, timeout)

	var allResults []*scanner.ScanResult

	for _, target := range targets {
		yellow.Printf("[>] Scanning %s ...\n", target)

		// Create scanner config
		cfg := &scanner.Config{
			Host:       target,
			Ports:      ports,
			Timeout:    time.Duration(timeout) * time.Millisecond,
			Threads:    threads,
			ScanType:   scanType,
			BannerGrab: bannerGrab,
			Verbose:    verbose,
		}

		s := scanner.New(cfg)
		result, err := s.Scan()
		if err != nil {
			red.Printf("[ERROR] Scanning %s: %v\n", target, err)
			continue
		}

		// OS Detection
		if osDetect {
			yellow.Printf("[*] Running OS detection on %s...\n", target)
			fp := fingerprint.New(target, time.Duration(timeout)*time.Millisecond)
			result.OS = fp.Detect(result.OpenPorts)
			if result.OS != "" {
				green.Printf("[+] OS Detected: %s\n", result.OS)
			}
		}

		// CVE Lookup
if cveCheck {
        yellow.Printf("[*] Looking up CVEs for detected services...\n")

        cveClient := cve.NewClient()

        for i, p := range result.OpenPorts {

                if p.Service != "" && p.Version != "" {

                        cves, err := cveClient.Lookup(p.Service, p.Version)

                        if err == nil && len(cves) > 0 {

                                // FIX: type conversion safe append
                                for _, c := range cves {

                                        result.OpenPorts[i].CVEs = append(
                                                result.OpenPorts[i].CVEs,
                                                scanner.CVEInfo{
                                                        ID:          c.ID,
                                                        Score:       c.Score,
                                                        Description: c.Description,
                                                },
                                        )
                                }

                                red.Printf(
                                        "[!] Port %d/%s (%s %s): %d CVE(s) found!\n",
                                        p.Port,
                                        p.Protocol,
                                        p.Service,
                                        p.Version,
                                        len(cves),
                                )

                                for _, c := range cves {

                                        desc := c.Description
                                        if len(desc) > 80 {
                                                desc = desc[:80]
                                        }

                                        fmt.Printf(
                                                "    %-20s CVSS:%.1f  %s\n",
                                                c.ID,
                                                c.Score,
                                                desc,
                                        )
                                }
                        }
                }
        }
}
		// Run Scripts
		if len(runScripts) > 0 {
			yellow.Printf("[*] Running scripts: %s\n", strings.Join(runScripts, ", "))
			engine := scripts.New()
			for _, scriptName := range runScripts {
				for i, p := range result.OpenPorts {
					output, err := engine.Run(scriptName, target, p.Port, p.Service)
					if err == nil && output != "" {
						result.OpenPorts[i].ScriptOutput = append(
							result.OpenPorts[i].ScriptOutput,
							fmt.Sprintf("[%s]\n%s", scriptName, output),
						)
					}
				}
			}
		}

		// Print results
		printResults(result, green, red, cyan, yellow)
		allResults = append(allResults, result)
	}

	elapsed := time.Since(startTime)
	bold.Printf("\n[*] Scan complete in %s\n", elapsed.Round(time.Millisecond))

	// Generate report
	if outputFile != "" {
		rep := report.New(outputFmt)
		if err := rep.Save(allResults, outputFile); err != nil {
			red.Printf("[ERROR] Saving report: %v\n", err)
		} else {
			green.Printf("[+] Report saved to: %s\n", outputFile)
		}
	}

	return nil
}

func printResults(result *scanner.ScanResult, green, red, cyan, yellow *color.Color) {
	fmt.Printf("\n")
	cyan.Printf("╔══════════════════════════════════════════════════╗\n")
	cyan.Printf("║  Host: %-42s║\n", result.Host)
	if result.OS != "" {
		cyan.Printf("║  OS:   %-42s║\n", result.OS)
	}
	cyan.Printf("╚══════════════════════════════════════════════════╝\n")

	if len(result.OpenPorts) == 0 {
		red.Println("  No open ports found.")
		return
	}

	fmt.Printf("  %-8s %-8s %-20s %-18s %s\n", "PORT", "STATE", "SERVICE", "VERSION", "BANNER/CVE")
	fmt.Println(strings.Repeat("─", 80))

	for _, p := range result.OpenPorts {
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		banner := p.Banner
		if len(banner) > 30 {
			banner = banner[:30] + "..."
		}

		cveCount := ""
		if len(p.CVEs) > 0 {
			cveCount = red.Sprintf(" [%d CVEs]", len(p.CVEs))
		}

		green.Printf("  %-8s %-8s %-20s %-18s %s%s\n",
			portStr, "open", p.Service, p.Version, banner, cveCount)

		// Print CVE details
		for _, c := range p.CVEs {
			severity := getSeverityColor(c.Score)
			fmt.Printf("           └─ %s %s (CVSS: %.1f)\n",
				severity(c.ID), c.Description[:min(50, len(c.Description))], c.Score)
		}

		// Print script output
		for _, out := range p.ScriptOutput {
			lines := strings.Split(out, "\n")
			for _, line := range lines {
				yellow.Printf("           │  %s\n", line)
			}
		}
	}
	fmt.Println()
}

func getSeverityColor(score float64) func(string, ...interface{}) string {
	switch {
	case score >= 9.0:
		return color.New(color.FgRed, color.Bold).Sprintf
	case score >= 7.0:
		return color.New(color.FgRed).Sprintf
	case score >= 4.0:
		return color.New(color.FgYellow).Sprintf
	default:
		return color.New(color.FgGreen).Sprintf
	}
}

func resolveTargets(host string) ([]string, error) {
	// CIDR support
	if strings.Contains(host, "/") {
		ip, ipNet, err := net.ParseCIDR(host)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", host)
		}
		var hosts []string
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			hosts = append(hosts, ip.String())
		}
		if len(hosts) > 2 {
			hosts = hosts[1 : len(hosts)-1]
		}
		return hosts, nil
	}

	// Multiple hosts
	if strings.Contains(host, ",") {
		return strings.Split(host, ","), nil
	}

	// Single host - resolve DNS
	if net.ParseIP(host) == nil {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %s: %v", host, err)
		}
		return addrs, nil
	}

	return []string{host}, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Top common ports
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 6379, 5432, 1521,
	2181, 9200, 9300, 11211, 6443, 2379, 4369, 5672, 15672, 61616,
}

func parsePorts(portStr string, topN int) ([]int, error) {
	if topN > 0 {
		if topN > len(commonPorts) {
			topN = len(commonPorts)
		}
		return commonPorts[:topN], nil
	}

	if portStr == "top" || portStr == "common" {
		return commonPorts, nil
	}

	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					ports = append(ports, i)
					seen[i] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	return ports, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
