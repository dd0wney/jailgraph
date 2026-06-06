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
