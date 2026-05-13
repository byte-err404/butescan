package cve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Client is the CVE lookup client
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	cache      map[string][]CVE
	mutex      sync.RWMutex
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
	ResultsPerPage int       `json:"resultsPerPage"`
	StartIndex     int       `json:"startIndex"`
	TotalResults   int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string      `json:"id"`
	Published    string      `json:"published"`
	LastModified string      `json:"lastModified"`
	Descriptions []nvdDesc   `json:"descriptions"`
	Metrics      nvdMetrics  `json:"metrics"`
	References   []nvdRef    `json:"references"`
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

	apiKey := os.Getenv("NVD_API_KEY")

	return &Client{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		apiKey:  apiKey,
		cache:   make(map[string][]CVE),
	}
}

// NewClientWithKey creates a CVE client with API key
func NewClientWithKey(apiKey string) *Client {

	c := NewClient()
	c.apiKey = apiKey

	return c
}

// Lookup searches for CVEs affecting a service/version
func (c *Client) Lookup(service, version string) ([]CVE, error) {

	cacheKey := strings.ToLower(service + ":" + version)

	// Cache check
	c.mutex.RLock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mutex.RUnlock()
		return cached, nil
	}
	c.mutex.RUnlock()

	keyword := buildKeyword(service, version)

	if keyword == "" {
		return nil, fmt.Errorf("cannot build keyword for %s %s", service, version)
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "10")

	reqURL := c.baseURL + "?" + params.Encode()

	var resp *http.Response
	var err error

	// Retry logic
	for retries := 0; retries < 3; retries++ {

		req, reqErr := http.NewRequest("GET", reqURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Butescan/1.0")

		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err = c.httpClient.Do(req)

		if err == nil {
			break
		}

		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %v", err)
	}

	defer resp.Body.Close()

	// Better status handling
	switch resp.StatusCode {

	case 200:

	case 403:
		return nil, fmt.Errorf("NVD API access denied or rate limited")

	case 429:
		return nil, fmt.Errorf("NVD API rate limit exceeded")

	case 503:
		return nil, fmt.Errorf("NVD API temporarily unavailable")

	default:
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse

	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %v", err)
	}

	var cves []CVE
	seen := make(map[string]bool)

	for _, v := range nvdResp.Vulnerabilities {

		cve := parseCVE(v.CVE)

		// Skip invalid
		if cve.Score <= 0 {
			continue
		}

		// Skip duplicates
		if seen[cve.ID] {
			continue
		}

		// Filter unrelated CVEs
		if !strings.Contains(
			strings.ToLower(cve.Description),
			strings.ToLower(service),
		) {
			continue
		}

		seen[cve.ID] = true

		cves = append(cves, cve)
	}

	// Sort by score
	sortCVEsByScore(cves)

	// Save cache
	c.mutex.Lock()
	c.cache[cacheKey] = cves
	c.mutex.Unlock()

	return cves, nil
}

// LookupByCVEID fetches a specific CVE
func (c *Client) LookupByCVEID(cveID string) (*CVE, error) {

	params := url.Values{}
	params.Set("cveId", cveID)

	reqURL := c.baseURL + "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Butescan/1.0")

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

	// Description
	for _, desc := range nvdCve.Descriptions {

		if desc.Lang == "en" {

			cve.Description = desc.Value

			// Trim huge descriptions
			if len(cve.Description) > 200 {
				cve.Description = cve.Description[:200] + "..."
			}

			break
		}
	}

	// CVSS
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

	productMap := map[string]string{
		"http":          "Apache HTTP Server",
		"https":         "nginx",
		"ssh":           "OpenSSH",
		"ftp":           "vsftpd",
		"smtp":          "Postfix",
		"mysql":         "MySQL",
		"postgresql":    "PostgreSQL",
		"redis":         "Redis",
		"mongodb":       "MongoDB",
		"elasticsearch": "Elasticsearch",
		"apache":        "Apache HTTP Server",
		"nginx":         "nginx",
		"iis":           "Microsoft IIS",
		"tomcat":        "Apache Tomcat",
		"wordpress":     "WordPress",
	}

	searchService := service

	if mapped, ok := productMap[strings.ToLower(service)]; ok {
		searchService = mapped
	}

	cleanVersion := extractCleanVersion(version)

	if cleanVersion != "" {
		return searchService + " " + cleanVersion
	}

	return searchService
}

func extractCleanVersion(version string) string {

	re := regexp.MustCompile(`\d+(\.\d+)+`)

	match := re.FindString(version)

	return match
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
