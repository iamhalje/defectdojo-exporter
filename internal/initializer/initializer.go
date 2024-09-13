package initializer

import (
	"defectdojo"
	"fmt"
)

// InitializeMetricsForProduct init all metrics
func InitializeMetricsForProduct(product string, severities []string, CWEs map[int]bool) {
	defectdojo.MU.Lock()
	defer defectdojo.MU.Unlock()

	if _, exists := defectdojo.PrevActive[product]; !exists {
		defectdojo.PrevActive[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevDuplicate[product]; !exists {
		defectdojo.PrevDuplicate[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevUnderReview[product]; !exists {
		defectdojo.PrevUnderReview[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevFalsePositive[product]; !exists {
		defectdojo.PrevFalsePositive[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevOutOfScope[product]; !exists {
		defectdojo.PrevOutOfScope[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevRiskAccepted[product]; !exists {
		defectdojo.PrevRiskAccepted[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevVerified[product]; !exists {
		defectdojo.PrevVerified[product] = make(map[string]float64)
	}
	if _, exists := defectdojo.PrevMitigated[product]; !exists {
		defectdojo.PrevMitigated[product] = make(map[string]float64)
	}

	for _, severity := range severities {
		for cwe := range CWEs {
			cweStr := fmt.Sprintf("%d", cwe)
			defectdojo.VulnActiveGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnDuplicateGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnUnderReviewGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnFalsePositiveGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnOutOfScopeGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnRiskAcceptedGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnVerifiedGauge.WithLabelValues(product, severity, cweStr)
			defectdojo.VulnMitigatedGauge.WithLabelValues(product, severity, cweStr)
		}
	}
}
