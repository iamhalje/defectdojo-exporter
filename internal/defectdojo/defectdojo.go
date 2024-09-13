package defectdojo

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	VulnActiveGauge        = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_active", Help: "Number of active vulnerabilities in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnDuplicateGauge     = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_duplicate", Help: "Number of duplicate vulnerabilities in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnUnderReviewGauge   = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_under_review", Help: "Number of vulnerabilities under review in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnFalsePositiveGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_false_positive", Help: "Number of false positive vulnerabilities in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnOutOfScopeGauge    = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_out_of_scope", Help: "Number of vulnerabilities out of scope in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnRiskAcceptedGauge  = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_risk_accepted", Help: "Number of vulnerabilities with risk accepted in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnVerifiedGauge      = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_verified", Help: "Number of verified vulnerabilities in DefectDojo"}, []string{"product", "severity", "cwe"})
	VulnMitigatedGauge     = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "dojo_vulnerabilities_mitigated", Help: "Number of mitigated vulnerabilities in DefectDojo"}, []string{"product", "severity", "cwe"})

	MU                sync.Mutex
	PrevActive        = make(map[string]map[string]float64)
	PrevDuplicate     = make(map[string]map[string]float64)
	PrevUnderReview   = make(map[string]map[string]float64)
	PrevFalsePositive = make(map[string]map[string]float64)
	PrevOutOfScope    = make(map[string]map[string]float64)
	PrevRiskAccepted  = make(map[string]map[string]float64)
	PrevVerified      = make(map[string]map[string]float64)
	PrevMitigated     = make(map[string]map[string]float64)
)

type Finding struct {
	Active       bool   `json:"active"`
	Severity     string `json:"severity"`
	CWE          int    `json:"cwe"`
	FalseP       bool   `json:"false_p"`
	Duplicate    bool   `json:"duplicate"`
	OutOfScope   bool   `json:"out_of_scope"`
	RiskAccepted bool   `json:"risk_accepted"`
	UnderReview  bool   `json:"under_review"`
	Verified     bool   `json:"verified"`
	Mitigated    bool   `json:"is_mitigated"`
}

type FindingsResponse struct {
	Next    string    `json:"next"`
	Results []Finding `json:"results"`
}

type Product struct {
	Name string `json:"name"`
}

type ProductsResponse struct {
	Next    string    `json:"next"`
	Results []Product `json:"results"`
}

// FetchProducts go to API DefectDojo products
func FetchProducts(url, token string) ([]string, error) {
	products := []string{}
	endpoint := fmt.Sprintf("%s/api/v2/products/", url)

	for endpoint != "" {
		resp, err := makeRequest(endpoint, token)
		if err != nil {
			log.Printf("Error fetching products: %v", err)
			return nil, err
		}
		var productsResp ProductsResponse
		if err := json.Unmarshal(resp, &productsResp); err != nil {
			log.Printf("Error unmarshalling products response: %v", err)
			return nil, err
		}

		for _, product := range productsResp.Results {
			products = append(products, product.Name)
		}

		endpoint = productsResp.Next
	}
	return products, nil
}

// FetchVulnerabilities go to api DefectDojo findings
func FetchVulnerabilities(product, url, token string) ([]Finding, error) {
	vulnerabilities := []Finding{}
	endpoint := fmt.Sprintf("%s/api/v2/findings/?product_name=%s&limit=100", url, product)

	for endpoint != "" {
		resp, err := makeRequest(endpoint, token)
		if err != nil {
			log.Printf("Error fetching vulnerabilities for product %s: %v", product, err)
			return nil, err
		}
		var findingsResp FindingsResponse
		if err := json.Unmarshal(resp, &findingsResp); err != nil {
			log.Printf("Error unmarshalling vulnerabilities response for product %s: %v", product, err)
			return nil, err
		}

		vulnerabilities = append(vulnerabilities, findingsResp.Results...)
		endpoint = findingsResp.Next
	}
	return vulnerabilities, nil
}

// CollectCWEs take all CWE in vulnerabilities
func CollectCWEs(vulnerabilities []Finding) map[int]bool {
	CWEs := make(map[int]bool)
	for _, vuln := range vulnerabilities {
		CWEs[vuln.CWE] = true
	}
	return CWEs
}

// makeRequest send request in API DefectDojo
func makeRequest(url, token string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}
