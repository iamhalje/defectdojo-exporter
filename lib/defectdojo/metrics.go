package defectdojo

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// VulnActiveGauge reports the number of active vulnerabilities in DefectDojo grouped by labels.
var VulnActiveGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_active", Help: "Number of active vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnDuplicateGauge reports the number of duplicate vulnerabilities in DefectDojo grouped by labels.
var VulnDuplicateGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_duplicate", Help: "Number of duplicate vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnUnderReviewGauge reports the number of vulnerabilities under review in DefectDojo grouped by labels.
var VulnUnderReviewGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_under_review", Help: "Number of vulnerabilities under review in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnFalsePositiveGauge reports the number of false positive vulnerabilities in DefectDojo grouped by labels.
var VulnFalsePositiveGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_false_positive", Help: "Number of false positive vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnOutOfScopeGauge reports the number of vulnerabilities out of scope in DefectDojo grouped by labels.
var VulnOutOfScopeGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_out_of_scope", Help: "Number of vulnerabilities out of scope in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnRiskAcceptedGauge reports the number of vulnerabilities with risk accepted in DefectDojo grouped by labels.
var VulnRiskAcceptedGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_risk_accepted", Help: "Number of vulnerabilities with risk accepted in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnVerifiedGauge reports the number of verified vulnerabilities in DefectDojo grouped by labels.
var VulnVerifiedGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_verified", Help: "Number of verified vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnMitigatedGauge reports the number of mitigated vulnerabilities in DefectDojo grouped by labels.
var VulnMitigatedGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_mitigated", Help: "Number of mitigated vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// PrevEngagementUpdateTimes caches the latest engagement update time per product name to skip unnecessary collection cycles.
var PrevEngagementUpdateTimes = make(map[string]time.Time)

// The following maps hold the previous metric values per product to correctly zero out metrics that disappeared.
var (
	PrevActive       = make(map[string]map[string]float64)
	PrevDuplicate    = make(map[string]map[string]float64)
	PrevUnderReview  = make(map[string]map[string]float64)
	PrevFalsePositive = make(map[string]map[string]float64)
	PrevOutOfScope   = make(map[string]map[string]float64)
	PrevRiskAccepted = make(map[string]map[string]float64)
	PrevVerified     = make(map[string]map[string]float64)
	PrevMitigated    = make(map[string]map[string]float64)
)

// MU guards access to shared state in this package.
var MU sync.Mutex