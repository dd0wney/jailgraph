// Package harden turns one program's observed behavior (a profile.Behavior)
// into an evidence-based hardening report: ranked, severity-tagged findings.
//
// Positioned against Lynis: evidence-based, not rule-based. Every finding cites
// what was OBSERVED. The hard part is honesty about what a given backend can
// even see — a seccomp trace cannot observe capabilities or namespaces, so those
// categories are gated on full (eBPF) coverage and, on a partial run, surface an
// explicit "not observable on this backend" finding rather than going silent
// (silence would read as "clean" — a false absence). For that reason the report
// emits NO single hardening score: a number computed over findings would rank a
// seccomp run higher than an eBPF run of the same program purely because it saw
// less. Output is ranked findings + a per-severity summary under a coverage label.
package harden

import (
	"sort"

	"github.com/dd0wney/jailgraph/internal/profile"
)

// Severity is a string enum (like audit.Mode) so --json is human-readable and
// rank() can drive sorting and the exit threshold.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// rank orders severities for sorting and the exit threshold. Higher = worse.
func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default: // SevInfo and unknown
		return 0
	}
}

// Finding is one evidence-based observation about the program's hardening posture.
type Finding struct {
	Category       string   `json:"category"` // capabilities | namespaces | syscalls | files | effectiveness | coverage
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"` // what was OBSERVED (or why it can't be)
	Recommendation string   `json:"recommendation"`
}

// Report is the full hardening report for one program (one run, or a union).
type Report struct {
	RunID    string    `json:"run_id"`
	Target   string    `json:"target"`
	Coverage string    `json:"coverage"` // "full (eBPF)" | "partial (seccomp/replay)"
	Lossy    bool      `json:"lossy"`
	Findings []Finding `json:"findings"`
}

// highRiskCaps are capabilities whose presence is a High finding (the rest are
// Medium). Tight, defensible set; expand only with evidence.
var highRiskCaps = map[string]bool{
	"CAP_SYS_ADMIN":       true,
	"CAP_SYS_MODULE":      true,
	"CAP_SYS_PTRACE":      true,
	"CAP_SYS_RAWIO":       true,
	"CAP_BPF":             true,
	"CAP_NET_ADMIN":       true,
	"CAP_DAC_READ_SEARCH": true,
	"CAP_SETUID":          true,
	"CAP_SETGID":          true,
}

// Analyze applies the v1 rule table to one (already collected/unioned) Behavior.
// Findings are returned sorted worst-first (by descending severity, then category,
// then title).
func Analyze(b profile.Behavior) Report {
	r := Report{RunID: b.RunID, Target: b.Target, Lossy: b.Lossy}
	if b.FullCoverage {
		r.Coverage = "full (eBPF)"
	} else {
		r.Coverage = "partial (seccomp/replay)"
	}
	add := func(cat string, sev Severity, title, ev, rec string) {
		r.Findings = append(r.Findings, Finding{Category: cat, Severity: sev, Title: title, Evidence: ev, Recommendation: rec})
	}

	// R8: a lossy trace degrades every finding below it (absence is not evidence
	// of absence), so flag it loudly.
	if b.Lossy {
		add("coverage", SevHigh, "trace was lossy — report is degraded",
			"the trace dropped events",
			"absence of a finding is not evidence of absence; re-run without drops before trusting this report")
	}

	// R1/R2/R3: capabilities, gated on full coverage. The seccomp backend cannot
	// observe cap_capable, so on a partial run we must NOT report "no caps" as if
	// it were evidence — we say so explicitly (R3) rather than going silent.
	if b.FullCoverage {
		for _, c := range b.Caps {
			sev := SevMedium
			if highRiskCaps[c] {
				sev = SevHigh
			}
			add("capabilities", sev, "capability held: "+c,
				"observed via cap_capable",
				"drop "+c+" if the program does not require it (firejail: omit from caps.keep)")
		}
		if len(b.Caps) == 0 {
			add("capabilities", SevInfo, "no capability use observed — program needs none",
				"full (eBPF) coverage observed no capability check",
				"set caps.drop all")
		}
	} else {
		// R3: honesty — do NOT go silent on a backend that can't see caps/NS.
		add("coverage", SevInfo, "capabilities and namespaces not observable on this backend",
			"seccomp/replay coverage cannot observe cap_capable or namespace creation",
			"re-run with --collector ebpf for capability and namespace findings")
	}

	finalize(&r)
	return r
}

// finalize sorts findings worst-first: descending severity, then category, then
// title — deterministic output for both RenderText and --json.
func finalize(r *Report) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() > b.Severity.rank()
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Title < b.Title
	})
}
