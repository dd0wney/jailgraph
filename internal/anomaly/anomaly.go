// Package anomaly is the offline behavioural anomaly detector. It generalizes the
// pairwise drift auditor (internal/audit) into a POPULATION model: it learns what
// is normal for a binary across all its recorded runs and scores a candidate
// run's NOVELTY — catching living-off-the-land (a known-good binary doing
// something it normally never does).
//
// It is statistical (per-item support frequency), not a learned model — but
// scoring goes through a pluggable Scorer interface (scorer.go) so a learned
// embedding scorer can slot in later. Honesty (mirrors detect/harden): the
// verdict is additive NOVELTY only (never "missing" behaviour, which partial
// execution/coverage confounds); files never drive the verdict; confidence
// scales with the baseline size; there is no single black-box score — every
// finding cites its support (e.g. "seen in 0/8 runs"). C2/exfil are out of scope
// (they need a network capture signal jailgraph does not have).
package anomaly

import (
	"fmt"
	"strings"

	"github.com/dd0wney/jailgraph/internal/profile"
)

// Analyze scores a candidate run's behaviour against the learned Baseline via the
// given Scorer. It always leads with a method disclaimer, notes lossy baseline
// exclusions, then appends the scorer's findings — additive novelty only, sorted
// worst-first.
func Analyze(cand profile.Behavior, base Baseline, scorer Scorer) Report {
	r := Report{RunID: cand.RunID, Target: base.Target, BaselineRuns: base.TotalRuns}
	add := func(cat string, sev Severity, title, ev, rec string) {
		r.Findings = append(r.Findings, Finding{cat, sev, title, ev, rec})
	}

	add("method", SevInfo, "population-novelty heuristic — additive only",
		fmt.Sprintf("flags behaviour this target never showed across %d prior run(s); novelty is suspicious, not proof", base.TotalRuns),
		"a novel syscall/binary can be a benign new code path — investigate, don't auto-block")
	if base.LossyExcluded > 0 {
		add("coverage", SevInfo, fmt.Sprintf("%d lossy baseline run(s) excluded", base.LossyExcluded),
			"lossy runs were dropped from the baseline — their absence of an item is not evidence",
			"re-trace those runs without drops to widen the baseline")
	}

	r.Findings = append(r.Findings, scorer.Score(base, cand)...)
	finalize(&r)
	return r
}

// finalize sorts findings worst-first (severity desc, then category, then title).
func finalize(r *Report) {
	for i := 1; i < len(r.Findings); i++ {
		for j := i; j > 0; j-- {
			a, b := r.Findings[j-1], r.Findings[j]
			less := a.Severity.rank() < b.Severity.rank() ||
				(a.Severity.rank() == b.Severity.rank() && (a.Category > b.Category ||
					(a.Category == b.Category && a.Title > b.Title)))
			if !less {
				break
			}
			r.Findings[j-1], r.Findings[j] = r.Findings[j], r.Findings[j-1]
		}
	}
}

// Severity is anomaly's own enum (no cross-import), so --json stays readable and
// rank() drives ordering + the exit gate.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevInfo     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 3
	case SevHigh:
		return 2
	case SevMedium:
		return 1
	default:
		return 0
	}
}

// DimBaseline is one dimension's population frequency table: Support maps an
// observed item (syscall name / exec'd binary / normalized file path / cap /
// network endpoint) to its support = the share of the N coverage-comparable
// baseline runs it appeared in. N is per-dimension so confidence and
// coverage-mismatch are one check.
type DimBaseline struct {
	Support map[string]float64
	N       int
}

// Baseline is the learned "normal" for a target across its run population.
type Baseline struct {
	Target                                     string
	Syscalls, Binaries, Files, Caps, Endpoints DimBaseline
	TotalRuns                                  int // same-target runs found (excl. candidate)
	LossyExcluded                              int // lossy runs dropped from support
	CandidateFullCoverage                      bool
}

// Finding is one observation. Category ∈ syscall|binary|file|cap|endpoint|coverage|method.
type Finding struct {
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

// Report is the anomaly result for one candidate run.
type Report struct {
	RunID        string    `json:"run_id"`
	Target       string    `json:"target"`
	BaselineRuns int       `json:"baseline_runs"`
	Findings     []Finding `json:"findings"`
}

var severityOrder = []Severity{SevCritical, SevHigh, SevMedium, SevInfo}

// HasHighOrAbove drives the CLI exit code (a High/Critical novelty → exit 1).
func (r Report) HasHighOrAbove() bool {
	for _, f := range r.Findings {
		if f.Severity.rank() >= SevHigh.rank() {
			return true
		}
	}
	return false
}

// RenderText leads with the baseline preamble (epistemic state), then findings
// grouped worst-first, then a per-severity summary.
func (r Report) RenderText() string {
	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f, a...); sb.WriteByte('\n') }

	w("behavioural anomaly scan")
	w("  target:   %s", r.Target)
	w("  run:      %s", r.RunID)
	w("  baseline: %d prior run(s) of this target", r.BaselineRuns)
	w("")

	counts := map[Severity]int{}
	for _, sev := range severityOrder {
		first := true
		for _, f := range r.Findings {
			if f.Severity != sev {
				continue
			}
			counts[sev]++
			if first {
				w("== %s ==", strings.ToUpper(string(sev)))
				first = false
			}
			w("[%s] %s", strings.ToUpper(string(sev)), f.Title)
			w("    evidence:  %s", f.Evidence)
			w("    recommend: %s", f.Recommendation)
		}
		if !first {
			w("")
		}
	}

	var parts []string
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], strings.ToUpper(string(sev[:1]))+string(sev[1:])))
		}
	}
	if len(parts) == 0 {
		parts = []string{"no findings"}
	}
	w("summary: %s", strings.Join(parts, ", "))
	return sb.String()
}
