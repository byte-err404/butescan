package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
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
	udpScan        bool
	topPorts       int
	verbose        bool
	versionDetect  bool
	aggressiveMode bool
	skipPing       bool
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
	Long: `A high-performance network scanning tool for security analysis.

Fast Rustscan-style scanner with Nmap-inspired detection.

Features:
  • TCP/UDP Port Scanning
  • Service & Version Detection
  • Vulnerability Enumeration
  • Banner Grabbing
  • OS Fingerprinting
  • Script Engine Support
  • JSON / HTML / Text Reporting

Examples:
  butescan -t 192.168.1.1
  butescan -t 10.0.0.0/24 --top-ports 100
  sudo butescan -t 192.168.1.1 -sS
  sudo butescan -t 192.168.1.1 -sU -p 53,161
  sudo butescan -t 192.168.1.1 -A

Notes:
  • SYN scan requires root privileges
  • UDP scans are slower than TCP scans`,
	RunE: runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {

	// Target Options
	rootCmd.Flags().StringVarP(&targetHost, "target", "t", "", "Target host/IP or CIDR range (required)")
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "Port range (e.g. 80,443 or 1-65535)")
	rootCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Scan top N common ports")

	// Performance
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 1000, "Timeout in milliseconds")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 1000, "Concurrent threads")

	// Scan Techniques
	rootCmd.Flags().StringVarP(&scanType, "scan-type", "s", "tcp", "Scan type: tcp, syn, udp, all")

	rootCmd.Flags().Bool("sS", false, "TCP SYN scan")
	rootCmd.Flags().Bool("sT", false, "TCP connect scan")
	rootCmd.Flags().Bool("sU", false, "UDP scan")

	// Detection
	rootCmd.Flags().BoolVarP(&versionDetect, "version-detect", "V", false, "Enable service/version detection")
	rootCmd.Flags().BoolVarP(&osDetect, "os", "O", false, "Enable OS fingerprinting")
	rootCmd.Flags().BoolVarP(&aggressiveMode, "aggressive", "A", false,
		"Enable OS detection, version detection and scripts")

	// Host Discovery
	rootCmd.Flags().BoolVar(&skipPing, "Pn", false,
		"Treat all hosts as online")

	// Enumeration
	rootCmd.Flags().BoolVar(&bannerGrab, "banner", true, "Enable banner grabbing")
	rootCmd.Flags().BoolVar(&cveCheck, "cve", false, "Check CVEs for detected services")

	rootCmd.Flags().StringSliceVar(
		&runScripts,
		"script",
		[]string{},
		"Comma-separated scripts to run",
	)

	// Output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&outputFmt, "format", "text", "Output format: text, json, html")

	// Misc
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {

	// Nmap-style scan shortcuts
	if syn, _ := cmd.Flags().GetBool("sS"); syn {
		scanType = "syn"
	}

	if tcp, _ := cmd.Flags().GetBool("sT"); tcp {
		scanType = "tcp"
	}

	if udp, _ := cmd.Flags().GetBool("sU"); udp {
		scanType = "udp"
	}

	// Aggressive mode
	if aggressiveMode {
		osDetect = true
		versionDetect = true
		bannerGrab = true
	}

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

	cyan.Printf(
		"[*] Targets: %d host(s) | Ports: %d | Threads: %d | Timeout: %dms\n\n",
		len(targets),
		len(ports),
		threads,
		timeout,
	)

	var allResults []*scanner.ScanResult

	for _, target := range targets {

		yellow.Printf("[>] Scanning %s ...\n", target)

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
