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

// VulnSLABreachedGauge reports the number of active vulnerabilities currently past their SLA deadline, grouped by labels.
var VulnSLABreachedGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_sla_breached", Help: "Number of active vulnerabilities past their SLA deadline in DefectDojo"},
	[]string{"product", "product_type", "severity", "cwe"},
)

// VulnMitigatedWithinSLAGauge reports the number of mitigated vulnerabilities fixed within their SLA.
var VulnMitigatedWithinSLAGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_mitigated_within_sla", Help: "Number of mitigated vulnerabilities fixed within their SLA in DefectDojo"},
	[]string{"product", "product_type", "severity"},
)

// VulnMitigatedOutsideSLAGauge reports the number of mitigated vulnerabilities fixed after their SLA deadline.
var VulnMitigatedOutsideSLAGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_mitigated_outside_sla", Help: "Number of mitigated vulnerabilities fixed after their SLA deadline in DefectDojo"},
	[]string{"product", "product_type", "severity"},
)

// VulnFixTimeDaysSumGauge reports the total days from discovery to mitigation across mitigated vulnerabilities.
// Divide by dojo_vulnerabilities_fix_time_days_count to get the average fix time.
var VulnFixTimeDaysSumGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_fix_time_days_sum", Help: "Total days from discovery to mitigation across mitigated vulnerabilities in DefectDojo"},
	[]string{"product", "product_type", "severity"},
)

// VulnFixTimeDaysCountGauge reports the number of mitigated vulnerabilities included in dojo_vulnerabilities_fix_time_days_sum.
var VulnFixTimeDaysCountGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "dojo_vulnerabilities_fix_time_days_count", Help: "Number of mitigated vulnerabilities included in dojo_vulnerabilities_fix_time_days_sum"},
	[]string{"product", "product_type", "severity"},
)

var PrevEngagementUpdateTimes = make(map[string]time.Time)

var (
	PrevActive        = make(map[string]map[string]float64)
	PrevDuplicate     = make(map[string]map[string]float64)
	PrevUnderReview   = make(map[string]map[string]float64)
	PrevFalsePositive = make(map[string]map[string]float64)
	PrevOutOfScope    = make(map[string]map[string]float64)
	PrevRiskAccepted  = make(map[string]map[string]float64)
	PrevVerified      = make(map[string]map[string]float64)
	PrevMitigated     = make(map[string]map[string]float64)
	PrevSLABreached   = make(map[string]map[string]float64)

	// Severity-keyed (product -> severity -> value) previous values for the
	// SLA compliance and fix-time metrics.
	PrevWithinSLA    = make(map[string]map[string]float64)
	PrevOutsideSLA   = make(map[string]map[string]float64)
	PrevFixTimeSum   = make(map[string]map[string]float64)
	PrevFixTimeCount = make(map[string]map[string]float64)
)

var MU sync.Mutex
