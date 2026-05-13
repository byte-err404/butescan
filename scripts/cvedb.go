package cvedb

import "strings"

// CVEEntry represents a known CVE with full details
type CVEEntry struct {
	ID          string
	Score       float64
	Severity    string
	Service     string
	Versions    []string // Affected versions (empty = all)
	Description string
	Impact      string
	PoC         string // Proof of concept info
	Mitigation  string
	References  []string
	Tags        []string // e.g. RCE, LFI, Auth Bypass, etc.
	Year        int
}

// KnownCVEs is the built-in offline CVE database
var KnownCVEs = []CVEEntry{
	// (তোমার পুরো CVE list এখানে 그대로 থাকবে — আমি ছোট করে দেখালাম না)
}

// LookupByService returns CVEs matching a given service name
func LookupByService(service string) []CVEEntry {
	svcLower := strings.ToLower(service)
	var results []CVEEntry

	serviceAliases := map[string][]string{
		"http":          {"http", "https", "web"},
		"https":         {"https", "http", "web"},
		"ssh":           {"ssh"},
		"ftp":           {"ftp"},
		"smtp":          {"smtp", "mail"},
		"mysql":         {"mysql", "mariadb"},
		"postgresql":    {"postgresql", "postgres"},
		"redis":         {"redis"},
		"mongodb":       {"mongodb", "mongo"},
		"elasticsearch": {"elasticsearch", "elastic"},
		"microsoft-ds":  {"microsoft-ds", "smb", "netbios"},
		"ms-wbt-server": {"ms-wbt-server", "rdp"},
		"vnc":           {"vnc"},
		"telnet":        {"telnet"},
		"dns":           {"dns"},
		"memcached":     {"memcached"},
		"amqp":          {"amqp", "rabbitmq"},
		"kubernetes-api": {"kubernetes-api", "kubernetes", "k8s"},
		"docker":        {"docker"},
	}

	aliases := serviceAliases[svcLower]
	if len(aliases) == 0 {
		aliases = []string{svcLower}
	}

	for _, cve := range KnownCVEs {
		for _, alias := range aliases {
			if strings.Contains(strings.ToLower(cve.Service), alias) ||
				strings.Contains(alias, strings.ToLower(cve.Service)) {
				results = append(results, cve)
				break
			}
		}
	}

	// sort by score (simple bubble sort)
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Score < results[j].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

// LookupCritical returns only CRITICAL severity CVEs for a service
func LookupCritical(service string) []CVEEntry {
	all := LookupByService(service)
	var critical []CVEEntry

	for _, c := range all {
		if c.Score >= 9.0 {
			critical = append(critical, c)
		}
	}
	return critical
}
