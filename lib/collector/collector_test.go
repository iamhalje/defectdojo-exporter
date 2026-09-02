package collector

import (
	"testing"
	"time"

	"github.com/iamhalje/defectdojo-exporter/lib/defectdojo"
)

func intPtr(i int) *int { return &i }

func timePtr(t time.Time) *time.Time { return &t }

func dojoDate(t time.Time) defectdojo.DojoDate { return defectdojo.DojoDate{Time: t} }

func TestAggregateFindingsStatuses(t *testing.T) {
	findings := []defectdojo.Finding{
		{Active: true, Severity: "Critical", CWE: 79},
		{Active: true, Severity: "Critical", CWE: 79},
		{Active: true, Verified: true, Severity: "High", CWE: 89},
		{Duplicate: true, Severity: "Medium", CWE: 22},
		{Mitigated: true, Severity: "Low", CWE: 0},
	}

	agg := aggregateFindings(findings)

	if got := agg.statuses[statusActive]["critical"]["79"]; got != 2 {
		t.Errorf("active critical cwe=79: got %v, want 2", got)
	}
	if got := agg.statuses[statusActive]["high"]["89"]; got != 1 {
		t.Errorf("active high cwe=89: got %v, want 1", got)
	}
	if got := agg.statuses[statusVerified]["high"]["89"]; got != 1 {
		t.Errorf("verified high cwe=89: got %v, want 1", got)
	}
	if got := agg.statuses[statusDuplicate]["medium"]["22"]; got != 1 {
		t.Errorf("duplicate medium cwe=22: got %v, want 1", got)
	}
	if got := agg.statuses[statusMitigated]["low"]["0"]; got != 1 {
		t.Errorf("mitigated low cwe=0: got %v, want 1", got)
	}
}

func TestAggregateFindingsSLABreached(t *testing.T) {
	findings := []defectdojo.Finding{
		// Active and past the SLA deadline: breached.
		{Active: true, Severity: "Critical", CWE: 79, SLADaysRemaining: intPtr(-5)},
		// Active with time left on the SLA: not breached.
		{Active: true, Severity: "High", CWE: 89, SLADaysRemaining: intPtr(10)},
		// Active with SLA disabled (null sla_days_remaining): not breached.
		{Active: true, Severity: "Medium", CWE: 22},
		// Past deadline but no longer active: not breached.
		{Mitigated: true, Severity: "Critical", CWE: 79, SLADaysRemaining: intPtr(-3)},
	}

	agg := aggregateFindings(findings)

	if got := agg.statuses[statusSLABreached]["critical"]["79"]; got != 1 {
		t.Errorf("sla_breached critical cwe=79: got %v, want 1", got)
	}
	if got := agg.statuses[statusSLABreached]["high"]["89"]; got != 0 {
		t.Errorf("sla_breached high cwe=89: got %v, want 0", got)
	}
	if got := agg.statuses[statusSLABreached]["medium"]["22"]; got != 0 {
		t.Errorf("sla_breached medium cwe=22: got %v, want 0", got)
	}
}

func TestAggregateFindingsFixTime(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	findings := []defectdojo.Finding{
		// Fixed in 2 days.
		{Mitigated: true, Severity: "Critical", CWE: 79, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, 2)), SLADaysRemaining: intPtr(5)},
		// Fixed in 28 days.
		{Mitigated: true, Severity: "Critical", CWE: 79, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, 28)), SLADaysRemaining: intPtr(-21)},
		// Mitigated timestamp before discovery date (data anomaly): clamped to 0 days.
		{Mitigated: true, Severity: "High", CWE: 89, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, -1)), SLADaysRemaining: intPtr(1)},
		// Duplicate findings are excluded from fix-time stats.
		{Duplicate: true, Mitigated: true, Severity: "High", CWE: 89, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, 4)), SLADaysRemaining: intPtr(1)},
		// No mitigated timestamp: excluded from fix-time stats.
		{Mitigated: true, Severity: "Low", CWE: 0, Date: dojoDate(base)},
	}

	agg := aggregateFindings(findings)

	if got := agg.fixTimeDaysSum["critical"]; got != 30 {
		t.Errorf("fix time sum critical: got %v, want 30", got)
	}
	if got := agg.fixTimeDaysCount["critical"]; got != 2 {
		t.Errorf("fix time count critical: got %v, want 2", got)
	}
	if got := agg.fixTimeDaysSum["high"]; got != 0 {
		t.Errorf("fix time sum high: got %v, want 0 (clamped anomaly only)", got)
	}
	if got := agg.fixTimeDaysCount["high"]; got != 1 {
		t.Errorf("fix time count high: got %v, want 1 (duplicate excluded)", got)
	}
	if _, ok := agg.fixTimeDaysCount["low"]; ok {
		t.Errorf("fix time count low should be absent when mitigated timestamp is missing")
	}
}

func TestAggregateFindingsMitigatedSLA(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	findings := []defectdojo.Finding{
		// Fixed with 5 days to spare: within SLA.
		{Mitigated: true, Severity: "Critical", CWE: 79, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, 2)), SLADaysRemaining: intPtr(5)},
		// Fixed 21 days past the deadline: outside SLA.
		{Mitigated: true, Severity: "Critical", CWE: 79, Date: dojoDate(base), MitigatedAt: timePtr(base.AddDate(0, 0, 28)), SLADaysRemaining: intPtr(-21)},
		// Fixed exactly on the deadline: within SLA.
		{Mitigated: true, Severity: "Low", CWE: 0, SLADaysRemaining: intPtr(0)},
		// SLA disabled: excluded from SLA stats.
		{Mitigated: true, Severity: "Medium", CWE: 22},
		// Duplicates are excluded from SLA stats.
		{Duplicate: true, Mitigated: true, Severity: "High", CWE: 89, SLADaysRemaining: intPtr(1)},
		// Active findings are not counted as mitigated within SLA.
		{Active: true, Severity: "High", CWE: 89, SLADaysRemaining: intPtr(3)},
	}

	agg := aggregateFindings(findings)

	if got := agg.mitigatedWithinSLA["critical"]; got != 1 {
		t.Errorf("within SLA critical: got %v, want 1", got)
	}
	if got := agg.mitigatedOutsideSLA["critical"]; got != 1 {
		t.Errorf("outside SLA critical: got %v, want 1", got)
	}
	if got := agg.mitigatedWithinSLA["low"]; got != 1 {
		t.Errorf("within SLA low: got %v, want 1", got)
	}
	if _, ok := agg.mitigatedWithinSLA["medium"]; ok {
		t.Errorf("medium should be absent from SLA stats when sla_days_remaining is null")
	}
	if _, ok := agg.mitigatedWithinSLA["high"]; ok {
		t.Errorf("high should be absent from within-SLA stats (duplicate and active excluded)")
	}
}
