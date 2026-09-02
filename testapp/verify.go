package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// expectation checks that the samples of one metric, filtered by a label
// subset and summed, equal want within tol. Summing across the cwe label
// keeps the checks independent of how findings map onto CWEs.
type expectation struct {
	desc   string
	metric string
	labels map[string]string
	want   float64
	tol    float64
}

func expectations(product string) []expectation {
	eq := func(desc, metric, severity string, want float64) expectation {
		return expectation{
			desc:   desc,
			metric: metric,
			labels: map[string]string{"product": product, "severity": severity},
			want:   want,
			tol:    0.01,
		}
	}
	return []expectation{
		eq("1 active critical finding", "dojo_vulnerabilities_active", "critical", 1),
		eq("1 active high finding", "dojo_vulnerabilities_active", "high", 1),
		eq("1 active medium finding", "dojo_vulnerabilities_active", "medium", 1),
		eq("1 critical finding breaching its SLA", "dojo_vulnerabilities_sla_breached", "critical", 1),
		eq("no high findings breaching their SLA", "dojo_vulnerabilities_sla_breached", "high", 0),
		eq("2 mitigated critical findings", "dojo_vulnerabilities_mitigated", "critical", 2),
		eq("1 critical finding fixed within SLA", "dojo_vulnerabilities_mitigated_within_sla", "critical", 1),
		eq("1 critical finding fixed outside SLA", "dojo_vulnerabilities_mitigated_outside_sla", "critical", 1),
		eq("critical fix time totals 30 days", "dojo_vulnerabilities_fix_time_days_sum", "critical", 30),
		eq("critical fix time covers 2 findings", "dojo_vulnerabilities_fix_time_days_count", "critical", 2),
	}
}

type sample struct {
	metric string
	labels map[string]string
	value  float64
}

var (
	sampleRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)$`)
	labelRe  = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
)

func parseMetrics(text string) []sample {
	var samples []sample
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := sampleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		labels := make(map[string]string)
		for _, lm := range labelRe.FindAllStringSubmatch(m[2], -1) {
			labels[lm[1]] = lm[2]
		}
		samples = append(samples, sample{metric: m[1], labels: labels, value: value})
	}
	return samples
}

// sumMatching sums every sample of the metric whose labels contain all of the
// wanted label values.
func sumMatching(samples []sample, metric string, labels map[string]string) float64 {
	var total float64
	for _, s := range samples {
		if s.metric != metric {
			continue
		}
		match := true
		for k, v := range labels {
			if s.labels[k] != v {
				match = false
				break
			}
		}
		if match {
			total += s.value
		}
	}
	return total
}

func fetchMetrics(exporterURL string) ([]sample, error) {
	resp, err := http.Get(exporterURL + "/metrics")
	if err != nil {
		return nil, err
	}
	defer closeBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s/metrics", resp.StatusCode, exporterURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseMetrics(string(body)), nil
}

// verifyMetrics polls the exporter until every expectation holds or the
// timeout expires, reporting the failing expectations either way.
func verifyMetrics(cfg config) error {
	expected := expectations(cfg.productName)
	deadline := time.Now().Add(cfg.verifyTimeout)

	var lastFailures []string
	for {
		samples, err := fetchMetrics(cfg.exporterURL)
		if err != nil {
			lastFailures = []string{fmt.Sprintf("fetching metrics: %v", err)}
		} else {
			lastFailures = nil
			for _, e := range expected {
				got := sumMatching(samples, e.metric, e.labels)
				if math.Abs(got-e.want) > e.tol {
					lastFailures = append(lastFailures,
						fmt.Sprintf("%s: %s%v = %v, want %v", e.desc, e.metric, e.labels, got, e.want))
				}
			}
		}

		if len(lastFailures) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		log.Printf("%d/%d expectations not met yet, retrying in 10s", len(lastFailures), len(expected))
		time.Sleep(10 * time.Second)
	}

	return fmt.Errorf("timed out after %s with %d unmet expectations:\n  %s",
		cfg.verifyTimeout, len(lastFailures), strings.Join(lastFailures, "\n  "))
}
