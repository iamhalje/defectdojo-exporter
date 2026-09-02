package main

import "testing"

const sampleMetrics = `# HELP dojo_vulnerabilities_active Number of active vulnerabilities in DefectDojo
# TYPE dojo_vulnerabilities_active gauge
dojo_vulnerabilities_active{cwe="89",product="exporter-testapp",product_type="Exporter Test",severity="critical"} 1
dojo_vulnerabilities_active{cwe="79",product="exporter-testapp",product_type="Exporter Test",severity="high"} 1
dojo_vulnerabilities_active{cwe="22",product="other-product",product_type="Other",severity="critical"} 3
dojo_vulnerabilities_fix_time_days_sum{product="exporter-testapp",product_type="Exporter Test",severity="critical"} 30
go_goroutines 12
`

func TestParseMetrics(t *testing.T) {
	samples := parseMetrics(sampleMetrics)
	if len(samples) != 5 {
		t.Fatalf("expected 5 samples, got %d", len(samples))
	}
	first := samples[0]
	if first.metric != "dojo_vulnerabilities_active" || first.labels["severity"] != "critical" || first.value != 1 {
		t.Errorf("unexpected first sample: %+v", first)
	}
	last := samples[4]
	if last.metric != "go_goroutines" || len(last.labels) != 0 || last.value != 12 {
		t.Errorf("unexpected label-less sample: %+v", last)
	}
}

func TestSumMatching(t *testing.T) {
	samples := parseMetrics(sampleMetrics)

	got := sumMatching(samples, "dojo_vulnerabilities_active", map[string]string{"product": "exporter-testapp", "severity": "critical"})
	if got != 1 {
		t.Errorf("critical active for exporter-testapp: got %v, want 1", got)
	}

	// Sums across the cwe label and ignores other products.
	got = sumMatching(samples, "dojo_vulnerabilities_active", map[string]string{"severity": "critical"})
	if got != 4 {
		t.Errorf("critical active across products: got %v, want 4", got)
	}

	got = sumMatching(samples, "dojo_vulnerabilities_sla_breached", map[string]string{"product": "exporter-testapp"})
	if got != 0 {
		t.Errorf("absent metric should sum to 0, got %v", got)
	}
}
