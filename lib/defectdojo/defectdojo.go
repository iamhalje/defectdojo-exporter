package defectdojo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// ErrAuthFailed is returned by FetchAPIToken when DefectDojo rejects the
// provided credentials, as opposed to transient network or availability errors.
var ErrAuthFailed = errors.New("defectdojo authentication failed")

const dojoDateLayout = "2006-01-02"

// DojoDate handles DefectDojo date-only JSON fields formatted as "2006-01-02".
type DojoDate struct {
	time.Time
}

func (d *DojoDate) UnmarshalJSON(data []byte) error {
	s := string(bytes.Trim(data, `"`))
	if s == "null" || s == "" {
		d.Time = time.Time{}
		return nil
	}
	t, err := time.Parse(dojoDateLayout, s)
	if err != nil {
		return err
	}
	d.Time = t
	return nil
}

func (d DojoDate) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + d.Format(dojoDateLayout) + `"`), nil
}

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
	// Date is the discovery date of the finding.
	Date DojoDate `json:"date"`
	// MitigatedAt is the timestamp the finding was mitigated, nil while open.
	MitigatedAt *time.Time `json:"mitigated"`
	// SLADaysRemaining is nil when SLA tracking is disabled for the finding.
	// For mitigated findings DefectDojo computes it against the mitigation
	// date, so a negative value means the fix landed after the SLA deadline.
	SLADaysRemaining *int `json:"sla_days_remaining"`
}

type FindingsResponse struct {
	Next    string    `json:"next"`
	Results []Finding `json:"results"`
}

type Product struct {
	ID   int    `json:"id"`
	Type int    `json:"prod_type"`
	Name string `json:"name"`
}

type ProductsResponse struct {
	Next    string    `json:"next"`
	Results []Product `json:"results"`
}

type Engagement struct {
	ID      int       `json:"id"`
	Product int       `json:"product"`
	Updated time.Time `json:"updated"`
}

type EngagementsResponse struct {
	Next    string       `json:"next"`
	Results []Engagement `json:"results"`
}

type Type struct {
	Name string `json:"name"`
}

type TypeResponse struct {
	Results []Type `json:"results"`
}

// FetchProducts retrieves the list of products
func FetchProducts(link, token string, timeout time.Duration) ([]Product, error) {
	products := []Product{}
	endpoint := fmt.Sprintf("%s/api/v2/products/", link)

	for endpoint != "" {
		resp, err := makeRequest(endpoint, token, timeout)
		if err != nil {
			log.Printf("Error fetching products: %v", err)
			return nil, err
		}
		var productsResp ProductsResponse
		if err := json.Unmarshal(resp, &productsResp); err != nil {
			log.Printf("Error unmarshalling products response: %v", err)
			return nil, err
		}

		products = append(products, productsResp.Results...)
		endpoint = productsResp.Next
	}
	return products, nil
}

// FetchVulnerabilities retrieves the list of findings
func FetchVulnerabilities(product, link, token string, timeout time.Duration) ([]Finding, error) {
	vulnerabilities := []Finding{}
	endpoint := fmt.Sprintf("%s/api/v2/findings/?product_name=%s&limit=100", link, url.PathEscape(product))

	for endpoint != "" {
		resp, err := makeRequest(endpoint, token, timeout)
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

// FetchProductType retrieves the product type name for the given product type ID.
func FetchProductType(productTypeID int, link, token string, timeout time.Duration) (string, error) {
	if name, ok := getCachedProductTypeName(productTypeID); ok {
		return name, nil
	}

	endpoint := fmt.Sprintf("%s/api/v2/product_types/?id=%d&limit=1", link, productTypeID)

	resp, err := makeRequest(endpoint, token, timeout)
	if err != nil {
		log.Printf("Error fetching product type for product %d: %v", productTypeID, err)
		return "", err
	}
	var productTypeResp TypeResponse
	if err := json.Unmarshal(resp, &productTypeResp); err != nil {
		log.Printf("Error unmarshalling product type response for product %d: %v", productTypeID, err)
		return "", err
	}

	if len(productTypeResp.Results) == 0 {
		return "", fmt.Errorf("no product type found for product %d", productTypeID)
	}

	name := productTypeResp.Results[0].Name
	setCacheProductTypeName(productTypeID, name)
	return name, nil
}

// FetchEngagementUpdatedTimestamp retrieves the timestamp of the most recent engagement
func FetchEngagementUpdatedTimestamp(product int, link, token string, timeout time.Duration) (time.Time, error) {
	var latestUpdate time.Time
	endpoint := fmt.Sprintf("%s/api/v2/engagements/?product=%d&limit=100", link, product)

	for endpoint != "" {
		resp, err := makeRequest(endpoint, token, timeout)
		if err != nil {
			log.Printf("Error fetching engagements for product %d: %v", product, err)
			return time.Time{}, err
		}

		var engagementResp EngagementsResponse
		if err := json.Unmarshal(resp, &engagementResp); err != nil {
			log.Printf("Error unmarshalling engagements response for product %d: %v", product, err)
			return time.Time{}, err
		}

		for _, engagement := range engagementResp.Results {
			if engagement.Updated.After(latestUpdate) {
				latestUpdate = engagement.Updated
			}
		}

		endpoint = engagementResp.Next
	}

	return latestUpdate, nil
}

// FetchAPIToken exchanges a username and password for a DefectDojo API token
// via /api/v2/api-token-auth/. Rejected credentials return ErrAuthFailed;
// any other failure (network, 5xx) is transient and safe to retry.
func FetchAPIToken(link, username, password string, timeout time.Duration) (string, error) {
	endpoint := fmt.Sprintf("%s/api/v2/api-token-auth/", link)

	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return "", err
	}

	client := getHTTPClient(timeout)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("HTTP error %d: %s: %w", resp.StatusCode, resp.Status, ErrAuthFailed)
	default:
		return "", fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("empty token in response from %s", endpoint)
	}
	return tokenResp.Token, nil
}

// makeRequest send request in API DefectDojo
func makeRequest(link, token string, timeout time.Duration) ([]byte, error) {
	client := getHTTPClient(timeout)
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}
