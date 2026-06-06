package harden

import (
	"strings"
	"testing"

	"github.com/dd0wney/jailgraph/internal/profile"
)

func TestSeverityRankOrder(t *testing.T) {
	order := []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
	for i := 0; i+1 < len(order); i++ {
		if order[i].rank() <= order[i+1].rank() {
			t.Errorf("%s.rank()=%d should be > %s.rank()=%d",
				order[i], order[i].rank(), order[i+1], order[i+1].rank())
		}
	}
	if SevInfo.rank() != 0 {
		t.Errorf("Info rank = %d, want 0", SevInfo.rank())
	}
}

// bh builds a Behavior fixture. fullCov marks eBPF-style full coverage.
func bh(fullCov, lossy bool, syscalls, files, caps, ns []string) profile.Behavior {
	m := map[string]bool{}
	for _, s := range syscalls {
		m[s] = true
	}
	return profile.Behavior{
		RunID: "r1", Target: "/bin/x", Syscalls: m, Files: files,
		Caps: caps, Namespaces: ns, Lossy: lossy, FullCoverage: fullCov,
	}
}

func has(r Report, cat string, sev Severity, titleSub string) bool {
	for _, f := range r.Findings {
		if f.Category == cat && f.Severity == sev && strings.Contains(f.Title, titleSub) {
			return true
		}
	}
	return false
}

func count(r Report, cat string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Category == cat {
			n++
		}
	}
	return n
}

func TestAnalyze_CapabilitiesAndCoverage(t *testing.T) {
	// eBPF run holding a high-risk cap -> High capabilities finding.
	r := Analyze(bh(true, false, nil, nil, []string{"CAP_SYS_ADMIN"}, nil))
	if !has(r, "capabilities", SevHigh, "CAP_SYS_ADMIN") {
		t.Errorf("expected High cap finding for CAP_SYS_ADMIN, got %+v", r.Findings)
	}
	// A non-high-risk cap on an eBPF run -> Medium.
	r = Analyze(bh(true, false, nil, nil, []string{"CAP_CHOWN"}, nil))
	if !has(r, "capabilities", SevMedium, "CAP_CHOWN") {
		t.Errorf("expected Medium cap finding for CAP_CHOWN, got %+v", r.Findings)
	}
	// eBPF run with no caps -> Info "needs none".
	r = Analyze(bh(true, false, nil, nil, nil, nil))
	if !has(r, "capabilities", SevInfo, "needs none") {
		t.Errorf("expected Info 'needs none', got %+v", r.Findings)
	}
	// Partial run -> NO cap findings, but an Info coverage finding (honesty rule).
	r = Analyze(bh(false, false, nil, nil, nil, nil))
	if count(r, "capabilities") != 0 {
		t.Errorf("partial run must not emit capability findings, got %+v", r.Findings)
	}
	if !has(r, "coverage", SevInfo, "not observable") {
		t.Errorf("expected partial-coverage Info finding, got %+v", r.Findings)
	}
	// Lossy -> High coverage finding.
	r = Analyze(bh(true, true, nil, nil, nil, nil))
	if !has(r, "coverage", SevHigh, "lossy") {
		t.Errorf("expected High lossy finding, got %+v", r.Findings)
	}
}
