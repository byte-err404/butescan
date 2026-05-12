package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"butescan/internal/scanner"
)

// Reporter generates scan reports
type Reporter struct {
	format string
}

// New creates a new Reporter
func New(format string) *Reporter {
	return &Reporter{format: strings.ToLower(format)}
}

// Save writes the scan results to a file
func (r *Reporter) Save(results []*scanner.ScanResult, filename string) error {
	switch r.format {
	case "json":
		return r.saveJSON(results, filename)
	case "html":
		return r.saveHTML(results, filename)
	default:
		return r.saveText(results, filename)
	}
}

// saveJSON writes JSON report
func (r *Reporter) saveJSON(results []*scanner.ScanResult, filename string) error {
	type JSONReport struct {
		GeneratedAt string                 `json:"generated_at"`
		TotalHosts  int                    `json:"total_hosts"`
		Results     []*scanner.ScanResult  `json:"results"`
	}

	report := JSONReport{
		GeneratedAt: time.Now().Format(time.RFC3339),
		TotalHosts:  len(results),
		Results:     results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// saveText writes plain text report
func (r *Reporter) saveText(results []*scanner.ScanResult, filename string) error {
	var sb strings.Builder

	sb.WriteString("GoScanner Report\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Total hosts scanned: %d\n\n", len(results)))

	for _, result := range results {
		sb.WriteString(fmt.Sprintf("Host: %s\n", result.Host))
		if result.IP != "" && result.IP != result.Host {
			sb.WriteString(fmt.Sprintf("IP:   %s\n", result.IP))
		}
		if result.OS != "" {
			sb.WriteString(fmt.Sprintf("OS:   %s\n", result.OS))
		}
		sb.WriteString(fmt.Sprintf("Scan: %s -> %s\n",
			result.StartTime.Format("15:04:05"),
			result.EndTime.Format("15:04:05")))
		sb.WriteString(strings.Repeat("-", 60) + "\n")

		if len(result.OpenPorts) == 0 {
			sb.WriteString("No open ports found.\n")
		} else {
			sb.WriteString(fmt.Sprintf("%-10s %-8s %-20s %-18s %s\n",
				"PORT", "STATE", "SERVICE", "VERSION", "BANNER"))
			sb.WriteString(strings.Repeat("-", 80) + "\n")

			for _, p := range result.OpenPorts {
				portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
				banner := p.Banner
				if len(banner) > 30 {
					banner = banner[:30]
				}
				sb.WriteString(fmt.Sprintf("%-10s %-8s %-20s %-18s %s\n",
					portStr, p.State, p.Service, p.Version, banner))

				// CVEs
				for _, c := range p.CVEs {
					sb.WriteString(fmt.Sprintf("  CVE: %s (CVSS: %.1f) %s\n",
						c.ID, c.Score, c.Description[:min(80, len(c.Description))]))
				}

				// Script output
				for _, out := range p.ScriptOutput {
					for _, line := range strings.Split(out, "\n") {
						sb.WriteString(fmt.Sprintf("  | %s\n", line))
					}
				}
			}
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

// saveHTML writes HTML report
func (r *Reporter) saveHTML(results []*scanner.ScanResult, filename string) error {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GoScanner Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --text: #e6edf3; --muted: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 20px; }
  h1 { color: var(--green); border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 20px; }
  h2 { color: var(--blue); margin: 20px 0 10px; }
  .summary { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 15px; margin-bottom: 20px; }
  .host-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 20px; overflow: hidden; }
  .host-header { background: #1c2128; padding: 12px 15px; border-bottom: 1px solid var(--border); }
  .host-header h2 { margin: 0; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #1c2128; padding: 8px 12px; text-align: left; color: var(--muted); font-size: 0.85em; border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 0.9em; }
  tr:last-child td { border-bottom: none; }
  .port-open { color: var(--green); font-weight: bold; }
  .cve-critical { color: #f85149; }
  .cve-high { color: #f0883e; }
  .cve-medium { color: #d29922; }
  .cve-low { color: var(--green); }
  .cve-block { background: #1c2128; border-left: 3px solid var(--red); padding: 8px; margin: 4px 0; font-size: 0.85em; }
  .script-block { background: #0d1117; border-left: 3px solid var(--blue); padding: 8px; margin: 4px 0; font-size: 0.85em; white-space: pre-wrap; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }
  .badge-critical { background: #3d1a1a; color: #f85149; }
  .badge-high { background: #2d1f0e; color: #f0883e; }
  .badge-medium { background: #2d2204; color: #d29922; }
  .badge-low { background: #0d2116; color: #3fb950; }
  .no-ports { padding: 20px; color: var(--muted); text-align: center; }
  .meta { color: var(--muted); font-size: 0.85em; margin-top: 4px; }
</style>
</head>
<body>
`)

	totalOpen := 0
	totalCVEs := 0
	for _, r := range results {
		totalOpen += len(r.OpenPorts)
		for _, p := range r.OpenPorts {
			totalCVEs += len(p.CVEs)
		}
	}

	sb.WriteString(fmt.Sprintf(`<h1>⚡ GoScanner Report</h1>
<div class="summary">
  <strong>Generated:</strong> %s<br>
  <strong>Hosts Scanned:</strong> %d &nbsp;|&nbsp;
  <strong>Open Ports Found:</strong> %d &nbsp;|&nbsp;
  <strong>CVEs Found:</strong> <span style="color:var(--red)">%d</span>
</div>
`, time.Now().Format("2006-01-02 15:04:05"), len(results), totalOpen, totalCVEs))

	for _, result := range results {
		sb.WriteString(`<div class="host-card">`)
		sb.WriteString(fmt.Sprintf(`<div class="host-header">
  <h2>%s</h2>`, result.Host))
		if result.IP != "" && result.IP != result.Host {
			sb.WriteString(fmt.Sprintf(`<div class="meta">IP: %s`, result.IP))
			if result.OS != "" {
				sb.WriteString(fmt.Sprintf(` | OS: %s`, result.OS))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</div>`)

		if len(result.OpenPorts) == 0 {
			sb.WriteString(`<div class="no-ports">No open ports found</div>`)
		} else {
			sb.WriteString(`<table>
<thead><tr>
  <th>PORT</th><th>STATE</th><th>SERVICE</th><th>VERSION</th><th>BANNER / CVEs / SCRIPTS</th>
</tr></thead><tbody>`)

			for _, p := range result.OpenPorts {
				banner := p.Banner
				if len(banner) > 60 {
					banner = banner[:60] + "..."
				}

				sb.WriteString(fmt.Sprintf(`<tr>
  <td><strong>%d/%s</strong></td>
  <td class="port-open">open</td>
  <td>%s</td>
  <td>%s</td>
  <td>%s`, p.Port, p.Protocol, p.Service, p.Version, banner))

				// CVEs
				if len(p.CVEs) > 0 {
					sb.WriteString("<br>")
					for _, c := range p.CVEs {
						sev := cveSeverity(c.Score)
						desc := c.Description
						if len(desc) > 100 {
							desc = desc[:100] + "..."
						}
						sb.WriteString(fmt.Sprintf(
							`<div class="cve-block"><span class="badge badge-%s">CVSS %.1f</span> <strong>%s</strong> %s</div>`,
							strings.ToLower(sev), c.Score, c.ID, desc))
					}
				}

				// Scripts
				for _, out := range p.ScriptOutput {
					sb.WriteString(fmt.Sprintf(`<div class="script-block">%s</div>`, out))
				}

				sb.WriteString(`</td></tr>`)
			}

			sb.WriteString(`</tbody></table>`)
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</body></html>`)

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

func cveSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
