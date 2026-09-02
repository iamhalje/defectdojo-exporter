package defectdojo

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFetchProducts(t *testing.T) {
	mockProducts := ProductsResponse{
		Next: "",
		Results: []Product{
			{
				ID:   1,
				Type: 2,
				Name: "Test Product 1",
			},
			{
				ID:   2,
				Type: 3,
				Name: "Test Product 2",
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Token dummy-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockProducts); err != nil {
			t.Fatalf("failed to encode mockProducts: %v", err)
		}
	}))
	defer ts.Close()

	products, err := FetchProducts(ts.URL, "dummy-token", 30*time.Second)
	if err != nil {
		t.Fatalf("FetchProducts error: %v", err)
	}

	if len(products) != len(mockProducts.Results) {
		t.Errorf("Expected %d products, got %d", len(mockProducts.Results), len(products))
	}

	for i, product := range products {
		expected := mockProducts.Results[i]
		if product.ID != expected.ID || product.Name != expected.Name || product.Type != expected.Type {
			t.Errorf("Mismatch at product %d: got %+v, want %+v", i, product, expected)
		}
	}
}

func TestFetchFindings(t *testing.T) {
	mockFindings := FindingsResponse{
		Next: "",
		Results: []Finding{
			{
				Active:       true,
				Severity:     "critical",
				CWE:          101,
				FalseP:       false,
				Duplicate:    false,
				OutOfScope:   false,
				RiskAccepted: true,
				UnderReview:  true,
				Verified:     true,
				Mitigated:    true,
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Token dummy-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockFindings); err != nil {
			t.Errorf("failed to encode mockFindings: %v", err)
		}
	}))
	defer ts.Close()

	findings, err := FetchVulnerabilities("Test Product", ts.URL, "dummy-token", 30*time.Second)
	if err != nil {
		t.Fatalf("FetchFindings error: %v", err)
	}

	if len(findings) != len(mockFindings.Results) {
		t.Errorf("Unexpected %d findings, got %d", len(mockFindings.Results), len(findings))
	}

	for i, finding := range findings {
		expected := mockFindings.Results[i]
		if !reflect.DeepEqual(finding, expected) {
			t.Errorf("Finding %d mismatch:\ngot %+v\nwant %+v", i, finding, expected)
		}
	}
}

func TestFindingUnmarshalDatesAndSLA(t *testing.T) {
	payload := `{
		"next": null,
		"results": [
			{
				"active": false,
				"severity": "Critical",
				"cwe": 79,
				"is_mitigated": true,
				"date": "2026-08-01",
				"mitigated": "2026-08-03T10:30:00Z",
				"sla_days_remaining": -5
			},
			{
				"active": true,
				"severity": "High",
				"cwe": 89,
				"is_mitigated": false,
				"date": "2026-08-10",
				"mitigated": null,
				"sla_days_remaining": null
			}
		]
	}`

	var resp FindingsResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("unmarshal findings: %v", err)
	}

	first := resp.Results[0]
	wantDate := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if !first.Date.Equal(wantDate) {
		t.Errorf("date: got %v, want %v", first.Date.Time, wantDate)
	}
	wantMitigated := time.Date(2026, 8, 3, 10, 30, 0, 0, time.UTC)
	if first.MitigatedAt == nil || !first.MitigatedAt.Equal(wantMitigated) {
		t.Errorf("mitigated: got %v, want %v", first.MitigatedAt, wantMitigated)
	}
	if first.SLADaysRemaining == nil || *first.SLADaysRemaining != -5 {
		t.Errorf("sla_days_remaining: got %v, want -5", first.SLADaysRemaining)
	}

	second := resp.Results[1]
	if second.MitigatedAt != nil {
		t.Errorf("mitigated should be nil, got %v", second.MitigatedAt)
	}
	if second.SLADaysRemaining != nil {
		t.Errorf("sla_days_remaining should be nil, got %v", second.SLADaysRemaining)
	}
}

func TestDojoDateRoundTrip(t *testing.T) {
	d := DojoDate{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"2026-08-01"` {
		t.Errorf("marshal: got %s, want \"2026-08-01\"", b)
	}

	var zero DojoDate
	b, err = json.Marshal(zero)
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("marshal zero: got %s, want null", b)
	}

	var parsed DojoDate
	if err := json.Unmarshal([]byte("null"), &parsed); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if !parsed.IsZero() {
		t.Errorf("unmarshal null: expected zero date, got %v", parsed.Time)
	}
}

func TestFetchAPIToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/api-token-auth/" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if creds.Username != "admin" || creds.Password != "secret" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"token": "dummy-token"}); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
	defer ts.Close()

	token, err := FetchAPIToken(ts.URL, "admin", "secret", 30*time.Second)
	if err != nil {
		t.Fatalf("FetchAPIToken error: %v", err)
	}
	if token != "dummy-token" {
		t.Errorf("Expected token 'dummy-token', got %q", token)
	}

	_, err = FetchAPIToken(ts.URL, "admin", "wrong", 30*time.Second)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("Expected ErrAuthFailed for bad credentials, got %v", err)
	}
}

func TestFetchProductsInvalidToken(t *testing.T) {
	// DefectDojo answers 403 (not 401) for unknown tokens; the error must be
	// classified as an auth failure and carry the response body so the cause
	// is visible in the logs.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"detail":"Invalid token."}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	_, err := FetchProducts(ts.URL, "bad-token", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "Invalid token") {
		t.Errorf("expected error to contain the response body, got %q", err.Error())
	}
}

func TestFetchProductType(t *testing.T) {
	mockProductType := TypeResponse{
		Results: []Type{
			{
				Name: "python",
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Token dummy-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockProductType); err != nil {
			t.Errorf("failed to encode mockProductType: %v", err)
		}
	}))
	defer ts.Close()

	types, err := FetchProductType(1, ts.URL, "dummy-token", 30*time.Second)
	if err != nil {
		t.Fatalf("FetchProductType error: %v", err)
	}

	if len(mockProductType.Results) == 0 {
		t.Errorf("Unexpected %d types, got %d", len(mockProductType.Results), len(types))
	}
}

func TestFetchEngagementUpdatedTimestamp(t *testing.T) {

	time1 := time.Date(2025, 06, 13, 11, 16, 13, 913679251, time.FixedZone("UTC+5", 5*60*60))
	time2 := time.Date(2025, 06, 13, 0, 0, 0, 0, time.UTC)

	mockEngagementUpdatedTimestamp := EngagementsResponse{
		Next: "",
		Results: []Engagement{
			{
				ID:      1,
				Product: 1,
				Updated: time1,
			},
			{
				ID:      2,
				Product: 1,
				Updated: time2,
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Token dummy-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockEngagementUpdatedTimestamp); err != nil {
			t.Errorf("failed to encode mockEngagementUpdatedTimestamp: %v", err)
		}
	}))
	defer ts.Close()

	latest, err := FetchEngagementUpdatedTimestamp(1, ts.URL, "dummy-token", 30*time.Second)
	if err != nil {
		t.Fatalf("FetchEngagementUpdatedTimestamp error: %v", err)
	}

	if !latest.Equal(time1) {
		t.Errorf("Expected latest timestamp %v, got %v", time1, latest)
	}
}
