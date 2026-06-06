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

func TestAnalyze_NamespacesSyscallsFiles(t *testing.T) {
	// R4: user NS -> High, net -> Medium, other -> Low (eBPF only).
	r := Analyze(bh(true, false, nil, nil, nil, []string{"user", "net", "mnt"}))
	if !has(r, "namespaces", SevHigh, "user") {
		t.Errorf("expected High user-namespace finding, got %+v", r.Findings)
	}
	if !has(r, "namespaces", SevMedium, "net") {
		t.Errorf("expected Medium net-namespace finding, got %+v", r.Findings)
	}
	if !has(r, "namespaces", SevLow, "mnt") {
		t.Errorf("expected Low mnt-namespace finding, got %+v", r.Findings)
	}
	// Partial run: namespaces NOT reported even if present (can't be trusted).
	r = Analyze(bh(false, false, nil, nil, nil, []string{"user"}))
	if count(r, "namespaces") != 0 {
		t.Errorf("partial run must not emit namespace findings, got %+v", r.Findings)
	}

	// R5: gateable syscall observed -> finding; setns Medium, openat Low.
	r = Analyze(bh(false, false, []string{"setns", "openat", "read"}, nil, nil, nil))
	if !has(r, "syscalls", SevMedium, "setns") {
		t.Errorf("expected Medium setns finding, got %+v", r.Findings)
	}
	if !has(r, "syscalls", SevLow, "openat") {
		t.Errorf("expected Low openat finding, got %+v", r.Findings)
	}
	// "read" is not gateable -> no finding.
	if has(r, "syscalls", SevLow, "read") || has(r, "syscalls", SevMedium, "read") {
		t.Errorf("non-gateable syscall must not be a finding, got %+v", r.Findings)
	}

	// R6: sensitive file -> High.
	r = Analyze(bh(false, false, nil, []string{"/etc/shadow", "/home/u/.ssh/id_rsa", "/etc/hostname"}, nil, nil))
	if !has(r, "files", SevHigh, "/etc/shadow") {
		t.Errorf("expected High /etc/shadow finding, got %+v", r.Findings)
	}
	if !has(r, "files", SevHigh, "id_rsa") {
		t.Errorf("expected High ssh-key finding, got %+v", r.Findings)
	}
	if count(r, "files") != 2 {
		t.Errorf("/etc/hostname must not be sensitive; want 2 file findings, got %d (%+v)", count(r, "files"), r.Findings)
	}

	// R7: effectiveness Info always present.
	if !has(r, "effectiveness", SevInfo, "would deny") {
		t.Errorf("expected effectiveness Info finding, got %+v", r.Findings)
	}
}
