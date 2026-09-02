// Command testapp seeds a running DefectDojo instance with a deterministic
// set of findings and then verifies that the defectdojo-exporter publishes
// the expected metric values for them. It is the integration test for the
// exporter and is wired into docker-compose.test.yml; it is not part of the
// exporter itself.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type config struct {
	dojoURL       string
	exporterURL   string
	username      string
	password      string
	productName   string
	waitTimeout   time.Duration
	verifyTimeout time.Duration
}

func loadConfig() config {
	cfg := config{
		dojoURL:       envOr("DD_URL", "http://nginx:8080"),
		exporterURL:   envOr("EXPORTER_URL", "http://exporter:8080"),
		username:      envOr("DD_USERNAME", "admin"),
		password:      os.Getenv("DD_PASSWORD"),
		productName:   envOr("SEED_PRODUCT", "exporter-testapp"),
		waitTimeout:   envDurationOr("WAIT_TIMEOUT", 15*time.Minute),
		verifyTimeout: envDurationOr("VERIFY_TIMEOUT", 5*time.Minute),
	}
	if cfg.password == "" {
		log.Fatal("DD_PASSWORD must be set")
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationOr(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid %s duration %q: %v", key, v, err)
	}
	return d
}

// seedFinding describes one finding to create. mitigatedAgoDays < 0 leaves
// the finding active; otherwise it is mitigated that many days in the past.
type seedFinding struct {
	title            string
	severity         string
	cwe              int
	ageDays          int
	mitigatedAgoDays int
}

// The seed set exercises every exporter metric with the default DefectDojo
// SLA configuration (Critical: 7 days, High: 30, Medium: 90, Low: 120):
//   - the 100-day-old active Critical breaches its SLA
//   - the Critical fixed in 2 days lands within SLA
//   - the Critical fixed in 28 days lands 21 days past its SLA deadline
//
// Fix time for Critical is therefore sum=30 days over count=2 findings.
var seedFindings = []seedFinding{
	{"SQL injection in login form", "Critical", 89, 100, -1},
	{"Reflected XSS in search", "High", 79, 2, -1},
	{"Weak TLS configuration", "Medium", 326, 1, -1},
	{"Hardcoded credential in config", "Critical", 798, 10, 8},
	{"Path traversal in file download", "Critical", 22, 40, 12},
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[testapp] ")

	cfg := loadConfig()

	log.Printf("Waiting for DefectDojo at %s (timeout %s)", cfg.dojoURL, cfg.waitTimeout)
	token, err := waitForToken(cfg)
	if err != nil {
		log.Fatalf("DefectDojo never became ready: %v", err)
	}
	log.Printf("Obtained API token for user %s", cfg.username)

	c := &dojoClient{baseURL: cfg.dojoURL, token: token, hc: &http.Client{Timeout: 60 * time.Second}}

	if err := c.deleteProductIfExists(cfg.productName); err != nil {
		log.Fatalf("Cleanup of previous seed data failed: %v", err)
	}

	if err := seed(c, cfg.productName); err != nil {
		log.Fatalf("Seeding failed: %v", err)
	}
	log.Printf("Seeded product %q with %d findings", cfg.productName, len(seedFindings))

	log.Printf("Verifying exporter metrics at %s/metrics (timeout %s)", cfg.exporterURL, cfg.verifyTimeout)
	if err := verifyMetrics(cfg); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	log.Print("PASS: all exporter metric expectations met")
}

// waitForToken polls the API token endpoint until DefectDojo answers,
// tolerating connection errors and 5xx while the stack boots.
func waitForToken(cfg config) (string, error) {
	deadline := time.Now().Add(cfg.waitTimeout)
	hc := &http.Client{Timeout: 30 * time.Second}
	for {
		token, err := fetchToken(hc, cfg.dojoURL, cfg.username, cfg.password)
		if err == nil {
			return token, nil
		}
		if errors.Is(err, errAuthRejected) {
			return "", err
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out after %s, last error: %w", cfg.waitTimeout, err)
		}
		log.Printf("DefectDojo not ready yet, retrying in 15s: %v", err)
		time.Sleep(15 * time.Second)
	}
}

var errAuthRejected = errors.New("credentials rejected")

func closeBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		log.Printf("Error closing response body: %v", err)
	}
}

func fetchToken(hc *http.Client, baseURL, username, password string) (string, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	resp, err := hc.Post(baseURL+"/api/v2/api-token-auth/", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("%w: HTTP %d: %s", errAuthRejected, resp.StatusCode, msg)
	default:
		return "", fmt.Errorf("HTTP %d from token endpoint", resp.StatusCode)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", errors.New("empty token in response")
	}
	return tokenResp.Token, nil
}

type dojoClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

// do sends an authenticated JSON request and decodes the response into out
// (which may be nil). Non-2xx responses become errors carrying the body.
func (c *dojoClient) do(method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type namedObject struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type listResponse struct {
	Results []namedObject `json:"results"`
}

// findByName returns the id of the object whose name matches exactly, since
// DefectDojo name filters match substrings.
func (c *dojoClient) findByName(path, name string) (int, bool, error) {
	var list listResponse
	if err := c.do(http.MethodGet, path+"?name="+url.QueryEscape(name)+"&limit=100", nil, &list); err != nil {
		return 0, false, err
	}
	for _, obj := range list.Results {
		if obj.Name == name {
			return obj.ID, true, nil
		}
	}
	return 0, false, nil
}

// ensureByName finds an object by exact name or creates it.
func (c *dojoClient) ensureByName(path, name string, payload any) (int, error) {
	id, found, err := c.findByName(path, name)
	if err != nil {
		return 0, err
	}
	if found {
		return id, nil
	}
	var created namedObject
	if err := c.do(http.MethodPost, path, payload, &created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// deleteProductIfExists removes a previous seed product so reruns stay
// deterministic. Deleting the product cascades to its engagements, tests and
// findings.
func (c *dojoClient) deleteProductIfExists(name string) error {
	id, found, err := c.findByName("/api/v2/products/", name)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	log.Printf("Deleting leftover product %q (id %d) from a previous run", name, id)
	return c.do(http.MethodDelete, fmt.Sprintf("/api/v2/products/%d/", id), nil, nil)
}

var numericalSeverity = map[string]string{
	"Critical": "S0",
	"High":     "S1",
	"Medium":   "S2",
	"Low":      "S3",
	"Info":     "S4",
}

func seed(c *dojoClient, productName string) error {
	base := time.Now().UTC().Truncate(24 * time.Hour)
	day := func(daysAgo int) time.Time { return base.AddDate(0, 0, -daysAgo) }

	productTypeID, err := c.ensureByName("/api/v2/product_types/", "Exporter Test",
		map[string]any{"name": "Exporter Test", "description": "Product type used by the defectdojo-exporter test app"})
	if err != nil {
		return fmt.Errorf("ensure product type: %w", err)
	}

	var product namedObject
	if err := c.do(http.MethodPost, "/api/v2/products/", map[string]any{
		"name":        productName,
		"description": "Deterministic seed data created by the defectdojo-exporter test app",
		"prod_type":   productTypeID,
	}, &product); err != nil {
		return fmt.Errorf("create product: %w", err)
	}

	var engagement namedObject
	if err := c.do(http.MethodPost, "/api/v2/engagements/", map[string]any{
		"name":            "exporter-testapp seed",
		"product":         product.ID,
		"target_start":    day(120).Format("2006-01-02"),
		"target_end":      base.AddDate(0, 0, 30).Format("2006-01-02"),
		"engagement_type": "Interactive",
		"status":          "In Progress",
	}, &engagement); err != nil {
		return fmt.Errorf("create engagement: %w", err)
	}

	testTypeID, err := c.ensureByName("/api/v2/test_types/", "Exporter Test",
		map[string]any{"name": "Exporter Test"})
	if err != nil {
		return fmt.Errorf("ensure test type: %w", err)
	}

	environmentID, err := c.ensureByName("/api/v2/development_environments/", "Development",
		map[string]any{"name": "Development"})
	if err != nil {
		return fmt.Errorf("ensure development environment: %w", err)
	}

	var test namedObject
	if err := c.do(http.MethodPost, "/api/v2/tests/", map[string]any{
		"engagement":   engagement.ID,
		"test_type":    testTypeID,
		"environment":  environmentID,
		"target_start": day(120).Format(time.RFC3339),
		"target_end":   base.AddDate(0, 0, 30).Format(time.RFC3339),
	}, &test); err != nil {
		return fmt.Errorf("create test: %w", err)
	}

	for _, f := range seedFindings {
		var created namedObject
		if err := c.do(http.MethodPost, "/api/v2/findings/", map[string]any{
			"test":               test.ID,
			"title":              f.title,
			"description":        "Seed finding created by the defectdojo-exporter test app",
			"severity":           f.severity,
			"numerical_severity": numericalSeverity[f.severity],
			"date":               day(f.ageDays).Format("2006-01-02"),
			"cwe":                f.cwe,
			"active":             true,
			"verified":           true,
			"duplicate":          false,
			"false_p":            false,
			"mitigation":         "n/a",
			"impact":             "n/a",
			"found_by":           []int{testTypeID},
		}, &created); err != nil {
			return fmt.Errorf("create finding %q: %w", f.title, err)
		}

		if f.mitigatedAgoDays >= 0 {
			// Requires DD_EDITABLE_MITIGATED_DATA=True on the uwsgi service
			// (set in docker-compose.test.yml).
			if err := c.do(http.MethodPatch, fmt.Sprintf("/api/v2/findings/%d/", created.ID), map[string]any{
				"active":       false,
				"is_mitigated": true,
				"mitigated":    day(f.mitigatedAgoDays).Format(time.RFC3339),
			}, nil); err != nil {
				return fmt.Errorf("mitigate finding %q: %w", f.title, err)
			}
		}
	}

	return nil
}
