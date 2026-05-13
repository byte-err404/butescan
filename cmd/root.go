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
	Use:   "butescan -t <target>",
	Short: "Advanced network scanner",
	RunE:  runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {

	rootCmd.Flags().StringVarP(&targetHost, "target", "t", "", "Target host/CIDR (required)")
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "Port range")
	rootCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Top ports")

	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 1000, "Timeout ms")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 1000, "Threads")

	// ===== NMAP STYLE FLAGS =====
	rootCmd.Flags().BoolP("A", "A", false, "Aggressive scan (OS + version + scripts)")
	rootCmd.Flags().BoolP("sV", "V", false, "Version detection")
	rootCmd.Flags().BoolP("O", "O", false, "OS detection")
	rootCmd.Flags().Bool("Pn", false, "Skip host discovery")
	rootCmd.Flags().String("T", "3", "Timing (0-5)")

	// ===== EXTRA =====
	rootCmd.Flags().BoolVar(&cveCheck, "cve", false, "CVE check")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")
	rootCmd.Flags().StringSliceVar(&runScripts, "script", []string{}, "Scripts")

	rootCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {

	// Colors
	green := color.New(color.FgGreen).PrintfFunc()
	red := color.New(color.FgRed).PrintfFunc()
	yellow := color.New(color.FgYellow).PrintfFunc()
	cyan := color.New(color.FgCyan).PrintfFunc()

	fmt.Println(banner)

	// ===== FLAGS LOGIC =====
	if aggressiveMode {
		osDetect = true
		versionDetect = true
		runScripts = append(runScripts, "http-headers", "ssh-hostkey")
	}

	if v, _ := cmd.Flags().GetBool("A"); v {
		osDetect = true
		versionDetect = true
		runScripts = append(runScripts, "http-headers")
	}

	if v, _ := cmd.Flags().GetBool("sV"); v {
		versionDetect = true
	}

	if v, _ := cmd.Flags().GetBool("O"); v {
		osDetect = true
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

	cyan("[*] Targets: %d | Ports: %d | Threads: %d\n",
		len(targets), len(ports), threads)

	var allResults []*scanner.ScanResult

	// ===== SCAN LOOP =====
	for _, target := range targets {

		yellow("[>] Scanning %s\n", target)

		cfg := &scanner.Config{
			Host:    target,
			Ports:   ports,
			Timeout: time.Duration(timeout) * time.Millisecond,
			Threads: threads,
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
		}

		// ===== CVE =====
		if cveCheck {
			client := cve.NewClient()
			for i, p := range result.OpenPorts {
				if p.Service != "" {
					cves, _ := client.Lookup(p.Service, p.Version)
					result.OpenPorts[i].CVEs = append(result.OpenPorts[i].CVEs, cves...)
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

	fmt.Printf("\n[*] Done in %s\n", time.Since(start))

	// ===== REPORT =====
	if outputFile != "" {
		rep := report.New(outputFmt)
		rep.Save(allResults, outputFile)
	}

	return nil
}
