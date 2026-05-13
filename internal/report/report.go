package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"butescan/internal/scanner"
)

// Reporter handles report generation
type Reporter struct {
	format string
}

// New creates a new reporter
func New(format string) *Reporter {
	return &Reporter{
		format: strings.ToLower(format),
	}
}

// Save exports reports
func (r *Reporter) Save(
	results []*scanner.ScanResult,
	filename string,
) error {

	switch r.format {

	case "json":
		return r.saveJSON(results, filename)

	case "html":
		return r.saveHTML(results, filename)

	default:
		return r.saveText(results, filename)
	}
}

// ======================
// JSON REPORT
// ======================

func (r *Reporter) saveJSON(
	results []*scanner.ScanResult,
	filename string,
) error {

	type JSONReport struct {
		Tool        string                  `json:"tool"`
		Version     string                  `json:"version"`
		GeneratedAt string                  `json:"generated_at"`
		TotalHosts  int                     `json:"total_hosts"`
		Results     []*scanner.ScanResult   `json:"results"`
	}

	report := JSONReport{
		Tool:        "Butescan",
		Version:     "v1.0",
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

// ======================
// TEXT REPORT
// ======================

func (r *Reporter) saveText(
	results []*scanner.ScanResult,
	filename string,
) error {

	var sb strings.Builder

	sb.WriteString(`
██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║   ██║   █████╗
██╔══██╗██║   ██║   ██║   ██╔══╝
██████╔╝╚██████╔╝   ██║   ███████╗
╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

`)
	sb.WriteString("Butescan Security Report\n")
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	sb.WriteString(fmt.Sprintf(
		"Generated: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
	))

	sb.WriteString(fmt.Sprintf(
		"Hosts Scanned: %d\n\n",
		len(results),
	))

	for _, result := range results {

		sb.WriteString(fmt.Sprintf(
			"Host: %s\n",
			result.Host,
		))

		if result.IP != "" &&
			result.IP != result.Host {

			sb.WriteString(fmt.Sprintf(
				"IP:   %s\n",
				result.IP,
			))
		}

		if result.OS != "" {

			sb.WriteString(fmt.Sprintf(
				"OS:   %s\n",
				result.OS,
			))
		}

		sb.WriteString(strings.Repeat("-", 70) + "\n")

		if len(result.OpenPorts) == 0 {

			sb.WriteString("No open ports found.\n\n")
			continue
		}

		sb.WriteString(fmt.Sprintf(
			"%-10s %-10s %-20s %-18s %s\n",
			"PORT",
			"STATE",
			"SERVICE",
			"VERSION",
			"BANNER",
		))

		sb.WriteString(strings.Repeat("-", 100) + "\n")

		for _, p := range result.OpenPorts {

			banner := p.Banner

			if len(banner) > 40 {
				banner = banner[:40] + "..."
			}

			sb.WriteString(fmt.Sprintf(
				"%-10s %-10s %-20s %-18s %s\n",
				fmt.Sprintf("%d/%s", p.Port, p.Protocol),
				"open",
				p.Service,
				p.Version,
				banner,
			))

			// CVEs
			for _, c := range p.CVEs {

				desc := c.Description

				if len(desc) > 80 {
					desc = desc[:80] + "..."
				}

				sb.WriteString(fmt.Sprintf(
					"   └─ %s | CVSS %.1f | %s\n",
					c.ID,
					c.Score,
					desc,
				))
			}

			// Script outputs
			for _, out := range p.ScriptOutput {

				lines := strings.Split(out, "\n")

				for _, line := range lines {

					if strings.TrimSpace(line) == "" {
						continue
					}

					sb.WriteString(fmt.Sprintf(
						"   │ %s\n",
						line,
					))
				}
			}
		}

		sb.WriteString("\n")
	}

	return os.WriteFile(
		filename,
		[]byte(sb.String()),
		0644,
	)
}

// ======================
// HTML REPORT
// ======================

func (r *Reporter) saveHTML(
	results []*scanner.ScanResult,
	filename string,
) error {

	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Butescan Report</title>

<style>

body{
	background:#0d1117;
	color:#e6edf3;
	font-family:Consolas, monospace;
	padding:20px;
}

h1{
	color:#3fb950;
}

.card{
	background:#161b22;
	border:1px solid #30363d;
	border-radius:10px;
	padding:15px;
	margin-bottom:20px;
}

table{
	width:100%;
	border-collapse:collapse;
	margin-top:10px;
}

th, td{
	padding:10px;
	border-bottom:1px solid #30363d;
	text-align:left;
}

th{
	background:#1c2128;
	color:#58a6ff;
}

.open{
	color:#3fb950;
	font-weight:bold;
}

.cve{
	background:#1c2128;
	padding:8px;
	margin-top:5px;
	border-left:3px solid #f85149;
}

.script{
	background:#11161d;
	padding:8px;
	margin-top:5px;
	border-left:3px solid #58a6ff;
	white-space:pre-wrap;
}

.badge{
	padding:2px 8px;
	border-radius:8px;
	font-size:12px;
	font-weight:bold;
}

.critical{
	background:#3d1a1a;
	color:#f85149;
}

.high{
	background:#38200f;
	color:#ff7b72;
}

.medium{
	background:#3a2d0b;
	color:#d29922;
}

.low{
	background:#0f2d17;
	color:#3fb950;
}

</style>
</head>
<body>
`)

	totalPorts := 0
	totalCVEs := 0

	for _, r := range results {

		totalPorts += len(r.OpenPorts)

		for _, p := range r.OpenPorts {
			totalCVEs += len(p.CVEs)
		}
	}

	sb.WriteString(fmt.Sprintf(`
<h1>⚡ Butescan Report</h1>

<div class="card">
	<b>Generated:</b> %s<br>
	<b>Hosts:</b> %d<br>
	<b>Open Ports:</b> %d<br>
	<b>CVEs:</b> %d
</div>
`,
		time.Now().Format("2006-01-02 15:04:05"),
		len(results),
		totalPorts,
		totalCVEs,
	))

	for _, result := range results {

		sb.WriteString(`<div class="card">`)

		sb.WriteString(fmt.Sprintf(
			"<h2>%s</h2>",
			html.EscapeString(result.Host),
		))

		if result.OS != "" {

			sb.WriteString(fmt.Sprintf(
				"<p><b>OS:</b> %s</p>",
				html.EscapeString(result.OS),
			))
		}

		if len(result.OpenPorts) == 0 {

			sb.WriteString("<p>No open ports found.</p>")
			sb.WriteString("</div>")
			continue
		}

		sb.WriteString(`
<table>
<tr>
<th>PORT</th>
<th>STATE</th>
<th>SERVICE</th>
<th>VERSION</th>
<th>BANNER / DETAILS</th>
</tr>
`)

		for _, p := range result.OpenPorts {

			banner := html.EscapeString(p.Banner)

			if len(banner) > 80 {
				banner = banner[:80] + "..."
			}

			sb.WriteString(fmt.Sprintf(`
<tr>
<td>%d/%s</td>
<td class="open">open</td>
<td>%s</td>
<td>%s</td>
<td>%s
`,
				p.Port,
				p.Protocol,
				html.EscapeString(p.Service),
				html.EscapeString(p.Version),
				banner,
			))

			// CVEs
			for _, c := range p.CVEs {

				sev := cveSeverity(c.Score)

				desc := html.EscapeString(c.Description)

				if len(desc) > 120 {
					desc = desc[:120] + "..."
				}

				sb.WriteString(fmt.Sprintf(`
<div class="cve">
<span class="badge %s">CVSS %.1f</span>
<b>%s</b><br>
%s
</div>
`,
					sev,
					c.Score,
					html.EscapeString(c.ID),
					desc,
				))
			}

			// Scripts
			for _, out := range p.ScriptOutput {

				sb.WriteString(fmt.Sprintf(`
<div class="script">%s</div>
`,
					html.EscapeString(out),
				))
			}

			sb.WriteString(`
</td>
</tr>
`)
		}

		sb.WriteString(`
</table>
</div>
`)
	}

	sb.WriteString(`
</body>
</html>
`)

	return os.WriteFile(
		filename,
		[]byte(sb.String()),
		0644,
	)
}

// CVE severity mapping
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
