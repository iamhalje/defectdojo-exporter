package collector

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/iamhalje/defectdojo-exporter/lib/defectdojo"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	statusActive        = "active"
	statusDuplicate     = "duplicate"
	statusUnderReview   = "under_review"
	statusFalsePositive = "false_positive"
	statusOutOfScope    = "out_of_scope"
	statusRiskAccepted  = "risk_accepted"
	statusVerified      = "verified"
	statusMitigated     = "mitigated"
	statusSLABreached   = "sla_breached"
)

const hoursPerDay = 24

type statusCountMap map[string]map[string]float64 // severity -> cwe -> count

// findingAggregates holds all per-product metric values derived from a
// findings snapshot.
type findingAggregates struct {
	statuses map[string]statusCountMap

	// Severity-keyed aggregates. Duplicate findings are excluded so they
	// don't skew SLA compliance and fix-time stats.
	fixTimeDaysSum      map[string]float64
	fixTimeDaysCount    map[string]float64
	mitigatedWithinSLA  map[string]float64
	mitigatedOutsideSLA map[string]float64
}

// aggregateFindings computes every exported metric value from a product's findings.
func aggregateFindings(findings []defectdojo.Finding) findingAggregates {
	agg := findingAggregates{
		statuses: map[string]statusCountMap{
			statusActive:        {},
			statusDuplicate:     {},
			statusUnderReview:   {},
			statusFalsePositive: {},
			statusOutOfScope:    {},
			statusRiskAccepted:  {},
			statusVerified:      {},
			statusMitigated:     {},
			statusSLABreached:   {},
		},
		fixTimeDaysSum:      make(map[string]float64),
		fixTimeDaysCount:    make(map[string]float64),
		mitigatedWithinSLA:  make(map[string]float64),
		mitigatedOutsideSLA: make(map[string]float64),
	}

	for _, vuln := range findings {
		severity := strings.ToLower(vuln.Severity)
		cwe := fmt.Sprintf("%d", vuln.CWE)

		if vuln.Active {
			increment(agg.statuses[statusActive], severity, cwe)
		}
		if vuln.Duplicate {
			increment(agg.statuses[statusDuplicate], severity, cwe)
		}
		if vuln.UnderReview {
			increment(agg.statuses[statusUnderReview], severity, cwe)
		}
		if vuln.FalseP {
			increment(agg.statuses[statusFalsePositive], severity, cwe)
		}
		if vuln.OutOfScope {
			increment(agg.statuses[statusOutOfScope], severity, cwe)
		}
		if vuln.RiskAccepted {
			increment(agg.statuses[statusRiskAccepted], severity, cwe)
		}
		if vuln.Verified {
			increment(agg.statuses[statusVerified], severity, cwe)
		}
		if vuln.Mitigated {
			increment(agg.statuses[statusMitigated], severity, cwe)
		}
		if vuln.Active && vuln.SLADaysRemaining != nil && *vuln.SLADaysRemaining < 0 {
			increment(agg.statuses[statusSLABreached], severity, cwe)
		}

		if vuln.Duplicate || !vuln.Mitigated {
			continue
		}

		if vuln.MitigatedAt != nil && !vuln.Date.IsZero() {
			days := vuln.MitigatedAt.Sub(vuln.Date.Time).Hours() / hoursPerDay
			if days < 0 {
				days = 0
			}
			agg.fixTimeDaysSum[severity] += days
			agg.fixTimeDaysCount[severity]++
		}

		if vuln.SLADaysRemaining != nil {
			if *vuln.SLADaysRemaining >= 0 {
				agg.mitigatedWithinSLA[severity]++
			} else {
				agg.mitigatedOutsideSLA[severity]++
			}
		}
	}

	return agg
}

// CollectMetrics main collector
func CollectMetrics(link, token string, concurrency int, interval time.Duration, timeout time.Duration, useEngagementUpdate bool) {
	limiter := make(chan struct{}, concurrency)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		products, err := defectdojo.FetchProducts(link, token, timeout)
		if err != nil {
			// DefectDojo may be temporarily unavailable (e.g. still starting
			// up); keep serving the last known metrics and retry next cycle.
			log.Printf("Error fetching products: %v", err)
			<-ticker.C
			continue
		}

		var wg sync.WaitGroup

		for _, p := range products {
			wg.Add(1)
			limiter <- struct{}{}

			go func(product string, productID int, productTypeID int) {
				defer wg.Done()
				defer func() { <-limiter }()

				if useEngagementUpdate {
					latestEngagementUpdate, err := defectdojo.FetchEngagementUpdatedTimestamp(productID, link, token, timeout)
					if err != nil {
						log.Printf("Error fetching engagement update time for product %s: %v", product, err)
						return
					}

					defectdojo.MU.Lock()
					prevUpdate, exists := defectdojo.PrevEngagementUpdateTimes[product]
					if exists && !latestEngagementUpdate.After(prevUpdate) {
						defectdojo.MU.Unlock()
						return
					}
					defectdojo.PrevEngagementUpdateTimes[product] = latestEngagementUpdate
					defectdojo.MU.Unlock()
				}

				productType, err := defectdojo.FetchProductType(productTypeID, link, token, timeout)
				if err != nil {
					log.Printf("Error fetching product type for product %s: %v", product, err)
					return
				}

				vulnerabilities, err := defectdojo.FetchVulnerabilities(product, link, token, timeout)
				if err != nil {
					log.Printf("Error fetching vulnerabilities for product %s: %v", product, err)
					return
				}

				agg := aggregateFindings(vulnerabilities)

				update := func(metric *prometheus.GaugeVec, prevMap map[string]map[string]float64, current statusCountMap) {
					defectdojo.MU.Lock()
					defer defectdojo.MU.Unlock()

					if prevMap[product] == nil {
						prevMap[product] = make(map[string]float64)
					}

					// Mark seen entries
					seen := make(map[string]bool)

					for severity, cweMap := range current {
						for cwe, count := range cweMap {
							labels := []string{product, productType, severity, cwe}
							metric.WithLabelValues(labels...).Set(count)
							prevMap[product][fmt.Sprintf("%s|%s", severity, cwe)] = count
							seen[fmt.Sprintf("%s|%s", severity, cwe)] = true
						}
					}

					// Set to 0 those that were present before but now not seen
					for key, prevVal := range prevMap[product] {
						if !seen[key] && prevVal != 0 {
							parts := strings.Split(key, "|")
							if len(parts) != 2 {
								continue
							}
							severity, cwe := parts[0], parts[1]
							labels := []string{product, productType, severity, cwe}
							metric.WithLabelValues(labels...).Set(0)
							prevMap[product][key] = 0
						}
					}
				}

				// updateBySeverity mirrors update for metrics keyed by severity only.
				updateBySeverity := func(metric *prometheus.GaugeVec, prevMap map[string]map[string]float64, current map[string]float64) {
					defectdojo.MU.Lock()
					defer defectdojo.MU.Unlock()

					if prevMap[product] == nil {
						prevMap[product] = make(map[string]float64)
					}

					seen := make(map[string]bool)

					for severity, value := range current {
						metric.WithLabelValues(product, productType, severity).Set(value)
						prevMap[product][severity] = value
						seen[severity] = true
					}

					for severity, prevVal := range prevMap[product] {
						if !seen[severity] && prevVal != 0 {
							metric.WithLabelValues(product, productType, severity).Set(0)
							prevMap[product][severity] = 0
						}
					}
				}

				update(defectdojo.VulnActiveGauge, defectdojo.PrevActive, agg.statuses[statusActive])
				update(defectdojo.VulnDuplicateGauge, defectdojo.PrevDuplicate, agg.statuses[statusDuplicate])
				update(defectdojo.VulnUnderReviewGauge, defectdojo.PrevUnderReview, agg.statuses[statusUnderReview])
				update(defectdojo.VulnFalsePositiveGauge, defectdojo.PrevFalsePositive, agg.statuses[statusFalsePositive])
				update(defectdojo.VulnOutOfScopeGauge, defectdojo.PrevOutOfScope, agg.statuses[statusOutOfScope])
				update(defectdojo.VulnRiskAcceptedGauge, defectdojo.PrevRiskAccepted, agg.statuses[statusRiskAccepted])
				update(defectdojo.VulnVerifiedGauge, defectdojo.PrevVerified, agg.statuses[statusVerified])
				update(defectdojo.VulnMitigatedGauge, defectdojo.PrevMitigated, agg.statuses[statusMitigated])
				update(defectdojo.VulnSLABreachedGauge, defectdojo.PrevSLABreached, agg.statuses[statusSLABreached])

				updateBySeverity(defectdojo.VulnMitigatedWithinSLAGauge, defectdojo.PrevWithinSLA, agg.mitigatedWithinSLA)
				updateBySeverity(defectdojo.VulnMitigatedOutsideSLAGauge, defectdojo.PrevOutsideSLA, agg.mitigatedOutsideSLA)
				updateBySeverity(defectdojo.VulnFixTimeDaysSumGauge, defectdojo.PrevFixTimeSum, agg.fixTimeDaysSum)
				updateBySeverity(defectdojo.VulnFixTimeDaysCountGauge, defectdojo.PrevFixTimeCount, agg.fixTimeDaysCount)

			}(p.Name, p.ID, p.Type)
		}
		wg.Wait()

		// Wait for the next tick. If the iteration took longer than the
		// interval, a tick is already buffered and collection resumes
		// immediately without building up a backlog.
		<-ticker.C
	}
}

func increment(m map[string]map[string]float64, severity, cwe string) {
	if m[severity] == nil {
		m[severity] = make(map[string]float64)
	}
	m[severity][cwe]++
}
