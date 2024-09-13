package collector

import (
	"defectdojo"
	"fmt"
	"initializer"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CollectMetrics main collector
func CollectMetrics(url, token string) {
	for {
		products, err := defectdojo.FetchProducts(url, token)
		if err != nil {
			log.Printf("Error fetching products: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		var wg sync.WaitGroup

		for _, product := range products {
			wg.Add(1)
			go func(product string) {
				defer wg.Done()
				vulnerabilities, err := defectdojo.FetchVulnerabilities(product, url, token)
				if err != nil {
					log.Printf("Error fetching vulnerabilities for product %s: %v", product, err)
					return
				}

				severities := []string{"critical", "high", "medium", "low", "info"}
				CWEs := defectdojo.CollectCWEs(vulnerabilities)
				initializer.InitializeMetricsForProduct(product, severities, CWEs)

				// Aggregate counts
				activeCounts := make(map[string]map[string]float64)
				duplicateCounts := make(map[string]map[string]float64)
				underReviewCounts := make(map[string]map[string]float64)
				falsePositiveCounts := make(map[string]map[string]float64)
				outOfScopeCounts := make(map[string]map[string]float64)
				riskAcceptedCounts := make(map[string]map[string]float64)
				verifiedCounts := make(map[string]map[string]float64)
				mitigatedCounts := make(map[string]map[string]float64)

				// Initialize maps
				for _, severity := range severities {
					activeCounts[severity] = make(map[string]float64)
					duplicateCounts[severity] = make(map[string]float64)
					underReviewCounts[severity] = make(map[string]float64)
					falsePositiveCounts[severity] = make(map[string]float64)
					outOfScopeCounts[severity] = make(map[string]float64)
					riskAcceptedCounts[severity] = make(map[string]float64)
					verifiedCounts[severity] = make(map[string]float64)
					mitigatedCounts[severity] = make(map[string]float64)

					// default value 0
					for _, vuln := range vulnerabilities {
						cwe := fmt.Sprintf("%d", vuln.CWE)
						activeCounts[severity][cwe] = 0
						duplicateCounts[severity][cwe] = 0
						underReviewCounts[severity][cwe] = 0
						falsePositiveCounts[severity][cwe] = 0
						outOfScopeCounts[severity][cwe] = 0
						riskAcceptedCounts[severity][cwe] = 0
						verifiedCounts[severity][cwe] = 0
						mitigatedCounts[severity][cwe] = 0
					}
				}

				// Aggregate the number of vulnerabilities by severity and CWE
				for _, vuln := range vulnerabilities {

					severity := strings.ToLower(vuln.Severity)
					cwe := fmt.Sprintf("%d", vuln.CWE)

					if vuln.Active {
						activeCounts[severity][cwe]++
					}
					if vuln.Duplicate {
						duplicateCounts[severity][cwe]++
					}
					if vuln.UnderReview {
						underReviewCounts[severity][cwe]++
					}
					if vuln.FalseP {
						falsePositiveCounts[severity][cwe]++
					}
					if vuln.OutOfScope {
						outOfScopeCounts[severity][cwe]++
					}
					if vuln.RiskAccepted {
						riskAcceptedCounts[severity][cwe]++
					}
					if vuln.Verified {
						verifiedCounts[severity][cwe]++
					}
					if vuln.Mitigated {
						mitigatedCounts[severity][cwe]++
					}
				}

				for severity, cweMap := range activeCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnActiveGauge, defectdojo.PrevActive, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range duplicateCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnDuplicateGauge, defectdojo.PrevDuplicate, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range underReviewCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnUnderReviewGauge, defectdojo.PrevUnderReview, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range falsePositiveCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnFalsePositiveGauge, defectdojo.PrevFalsePositive, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range outOfScopeCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnOutOfScopeGauge, defectdojo.PrevOutOfScope, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range riskAcceptedCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnRiskAcceptedGauge, defectdojo.PrevRiskAccepted, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range verifiedCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnVerifiedGauge, defectdojo.PrevVerified, product, severity, cwe, count)
					}
				}
				for severity, cweMap := range mitigatedCounts {
					for cwe, count := range cweMap {
						updateMetric(defectdojo.VulnMitigatedGauge, defectdojo.PrevMitigated, product, severity, cwe, count)
					}
				}
			}(product)
		}

		wg.Wait()
	}
}

// updateMetric updated metrics
func updateMetric(metric *prometheus.GaugeVec, prev map[string]map[string]float64, product, severity, cwe string, value float64) {
	defectdojo.MU.Lock()
	defer defectdojo.MU.Unlock()

	if prev[product] == nil {
		prev[product] = make(map[string]float64)
	}

	metric.WithLabelValues(product, severity, cwe).Set(value)
	prev[product][severity] = value
}
