package cve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the CVE lookup client
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// CVE represents a CVE entry
type CVE struct {
	ID          string
	Score       float64
	Severity    string
	Description string
	Published   string
	Modified    string
	References  []string
}

// NVD API response structures
type nvdResponse struct {
	ResultsPerPage  int         `json:"resultsPerPage"`
	StartIndex      int         `json:"startIndex"`
	TotalResults    int         `json:"totalResults"`
	Vulnerabilities []nvdVuln   `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string         `json:"id"`
	Published        string         `json:"published"`
	LastModified     string         `json:"lastModified"`
	Descriptions     []nvdDesc      `json:"descriptions"`
	Metrics          nvdMetrics     `json:"metrics"`
	References       []nvdRef       `json:"references"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSv31 `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSv30 `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSv2  `json:"cvssMetricV2"`
}

type nvdCVSSv31 struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSv30 struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSv2 struct {
	CVSSData nvdCVSSDataV2 `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSDataV2 struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdRef struct {
	URL string `json:"url"`
}

// NewClient creates a new CVE client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// NewClientWithKey creates a CVE client with NVD API key (higher rate limits)
func NewClientWithKey(apiKey string) *Client {
	c := NewClient()
	c.apiKey = apiKey
	return c
}

// Lookup searches for CVEs affecting a service/version
func (c *Client) Lookup(service, version string) ([]CVE, error) {
	// Build search keyword
	keyword := buildKeyword(service, version)
	if keyword == "" {
		return nil, fmt.Errorf("cannot build keyword for %s %s", service, version)
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "10")

	reqURL := c.baseURL + "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("NVD API rate limit reached (use --nvd-key for higher limits)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %v", err)
	}

	var cves []CVE
	for _, v := range nvdResp.Vulnerabilities {
		cve := parseCVE(v.CVE)
		if cve.Score > 0 {
			cves = append(cves, cve)
		}
	}

	// Sort by score (highest first)
	sortCVEsByScore(cves)

	return cves, nil
}

// LookupByCVEID fetches a specific CVE by ID
func (c *Client) LookupByCVEID(cveID string) (*CVE, error) {
	params := url.Values{}
	params.Set("cveId", cveID)

	reqURL := c.baseURL + "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}

	cve := parseCVE(nvdResp.Vulnerabilities[0].CVE)
	return &cve, nil
}

func parseCVE(nvdCve nvdCVE) CVE {
	cve := CVE{
		ID:        nvdCve.ID,
		Published: nvdCve.Published,
		Modified:  nvdCve.LastModified,
	}

	// Get English description
	for _, desc := range nvdCve.Descriptions {
		if desc.Lang == "en" {
			cve.Description = desc.Value
			break
		}
	}

	// Get CVSS score (prefer v3.1 > v3.0 > v2)
	if len(nvdCve.Metrics.CvssMetricV31) > 0 {
		m := nvdCve.Metrics.CvssMetricV31[0]
		cve.Score = m.CVSSData.BaseScore
		cve.Severity = m.CVSSData.BaseSeverity
	} else if len(nvdCve.Metrics.CvssMetricV30) > 0 {
		m := nvdCve.Metrics.CvssMetricV30[0]
		cve.Score = m.CVSSData.BaseScore
		cve.Severity = m.CVSSData.BaseSeverity
	} else if len(nvdCve.Metrics.CvssMetricV2) > 0 {
		cve.Score = nvdCve.Metrics.CvssMetricV2[0].CVSSData.BaseScore
		cve.Severity = scoreToSeverity(cve.Score)
	}

	// References
	for _, ref := range nvdCve.References {
		cve.References = append(cve.References, ref.URL)
	}

	return cve
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func buildKeyword(service, version string) string {
	// Map service names to product names for better CVE search
	productMap := map[string]string{
		"http":         "Apache nginx",
		"ssh":          "OpenSSH",
		"ftp":          "vsftpd ProFTPD",
		"smtp":         "Postfix Exim",
		"mysql":        "MySQL MariaDB",
		"postgresql":   "PostgreSQL",
		"redis":        "Redis",
		"mongodb":      "MongoDB",
		"elasticsearch": "Elasticsearch",
		"apache":       "Apache HTTP Server",
		"nginx":        "nginx",
		"iis":          "Microsoft IIS",
		"tomcat":       "Apache Tomcat",
		"wordpress":    "WordPress",
	}

	searchService := service
	if mapped, ok := productMap[strings.ToLower(service)]; ok {
		searchService = mapped
	}

	// Extract clean version number
	cleanVersion := extractCleanVersion(version)
	if cleanVersion != "" {
		return searchService + " " + cleanVersion
	}

	return searchService
}

func extractCleanVersion(version string) string {
	// Remove prefix like "OpenSSH_" or "Apache/"
	parts := strings.Fields(version)
	for _, part := range parts {
		// Find something that looks like a version number
		for i, c := range part {
			if c >= '0' && c <= '9' {
				v := part[i:]
				// Trim trailing non-version chars
				end := len(v)
				for j, ch := range v {
					if ch != '.' && !(ch >= '0' && ch <= '9') && ch != '-' {
						end = j
						break
					}
				}
				if end > 0 {
					return v[:end]
				}
			}
		}
	}
	return ""
}

func sortCVEsByScore(cves []CVE) {
	for i := 0; i < len(cves); i++ {
		for j := i + 1; j < len(cves); j++ {
			if cves[i].Score < cves[j].Score {
				cves[i], cves[j] = cves[j], cves[i]
			}
		}
	}
}
