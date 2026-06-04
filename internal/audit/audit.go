// Package audit compares a candidate run's behavior against a trusted baseline
// and reports drift. It powers two framings:
//
//   - security: did this run do dangerous things the baseline never did?
//     (additive drift in the stable dimensions = an anomaly signal).
//   - reproducibility: an impurity check for builds — drift in the stable
//     dimensions between runs of the same derivation. NOTE: this is impurity-
//     *signal* detection, not trace-equality. Reproducible builds guarantee
//     deterministic OUTPUT, not deterministic execution traces; volatile temp
//     paths and ordering vary legitimately, so file-path differences are
//     reported as low-confidence and never drive the verdict.
//
// Dimension confidence is deliberately unequal:
//   - Syscalls (the rare watched set): high signal — drives the verdict.
//   - Binaries (exec'd): medium signal — drives the verdict.
//   - Files: noisy (programs open /tmp/XXXX, /proc/<pid>/... every run), so
//     paths are normalized to bucket volatile segments and the result is
//     reported separately as low-confidence, NOT part of the verdict.
package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dd0wney/jailgraph/internal/profile"
)

// Mode selects how the verdict is computed.
type Mode string

const (
	// ModeSecurity flags only ADDITIVE drift (candidate did something new) in
	// the stable dimensions — the anomaly signal.
	ModeSecurity Mode = "security"
	// ModeReproducibility flags ANY (symmetric) stable-dimension drift between
	// runs of the same derivation.
	ModeReproducibility Mode = "reproducibility"
)

// DimDrift is the difference in one dimension between baseline and candidate.
type DimDrift struct {
	Added   []string `json:"added"`   // in candidate, not baseline
	Removed []string `json:"removed"` // in baseline, not candidate
}

func (d DimDrift) empty() bool    { return len(d.Added) == 0 && len(d.Removed) == 0 }
func (d DimDrift) additive() bool { return len(d.Added) > 0 }

// Report is the full drift comparison.
type Report struct {
	BaselineRuns []string `json:"baseline_runs"`
	CandidateRun string   `json:"candidate_run"`
	// Verdict dimensions.
	Syscalls DimDrift `json:"syscalls"`
	Binaries DimDrift `json:"binaries"`
	// Low-confidence dimension (normalized paths); informational only.
	Files DimDrift `json:"files_low_confidence"`
}

// Union merges several trusted baseline behaviors into one (delegating to
// profile.Union — the canonical, complete merge). Baseline quality is
// proportional to the number of trusted runs unioned: a single run undercounts
// legitimate behavior and produces false drift.
func Union(behaviors ...profile.Behavior) profile.Behavior {
	return profile.Union("", behaviors...)
}

// Diff compares candidate against the (already unioned) baseline.
func Diff(baseline, candidate profile.Behavior) Report {
	return Report{
		Syscalls: diffSets(setFromMap(baseline.Syscalls), setFromMap(candidate.Syscalls)),
		Binaries: diffSets(setFromSlice(baseline.Binaries), setFromSlice(candidate.Binaries)),
		Files:    diffSets(normalizeSet(baseline.Files), normalizeSet(candidate.Files)),
	}
}

// DriftDetected is the verdict, computed only from the stable dimensions
// (syscalls, binaries). File drift never drives it.
func (r Report) DriftDetected(mode Mode) bool {
	switch mode {
	case ModeReproducibility:
		return !r.Syscalls.empty() || !r.Binaries.empty()
	default: // security
		return r.Syscalls.additive() || r.Binaries.additive()
	}
}

// RenderText renders a human-readable report. The verdict line reflects the
// stable dimensions only; file drift is shown as a labeled low-confidence note.
func (r Report) RenderText(mode Mode) string {
	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f, a...); sb.WriteByte('\n') }

	w("drift audit (mode: %s)", mode)
	w("  baseline runs: %s", strings.Join(r.BaselineRuns, ", "))
	w("  candidate run: %s", r.CandidateRun)
	w("")
	writeDim(&sb, "syscalls (high confidence)", r.Syscalls)
	writeDim(&sb, "binaries (medium confidence)", r.Binaries)
	writeDim(&sb, "files (LOW confidence — normalized paths, informational only)", r.Files)
	w("")
	if r.DriftDetected(mode) {
		w("VERDICT: DRIFT DETECTED (stable dimensions)")
	} else {
		w("VERDICT: no drift in stable dimensions")
	}
	return sb.String()
}

func writeDim(sb *strings.Builder, title string, d DimDrift) {
	fmt.Fprintf(sb, "%s:\n", title)
	if d.empty() {
		fmt.Fprintln(sb, "  (none)")
		return
	}
	for _, a := range d.Added {
		fmt.Fprintf(sb, "  + %s\n", a)
	}
	for _, r := range d.Removed {
		fmt.Fprintf(sb, "  - %s\n", r)
	}
}

// volatile path prefixes whose contents are nondeterministic per run.
var volatilePrefixes = []string{"/tmp", "/var/tmp", "/run", "/dev/shm", "/proc"}

// digitRun matches LONG digit runs only (>=6) — pids, timestamps, random temp
// suffixes — deliberately NOT short numbers, so library versions (libc-2.35) and
// arch designators (x86_64) survive. File drift is the informational (non-verdict)
// dimension, so this normalization is intentionally lossy: it suppresses volatile
// noise without masking meaningful version/arch differences.
var digitRun = regexp.MustCompile(`[0-9]{6,}`)

// normalizePath buckets volatile paths (their contents are nondeterministic per
// run) and collapses long digit runs elsewhere.
func normalizePath(p string) string {
	for _, pre := range volatilePrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return pre + "/*"
		}
	}
	return digitRun.ReplaceAllString(p, "#")
}

func normalizeSet(paths []string) map[string]struct{} {
	out := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		out[normalizePath(p)] = struct{}{}
	}
	return out
}

func diffSets(baseline, candidate map[string]struct{}) DimDrift {
	var d DimDrift
	for k := range candidate {
		if _, ok := baseline[k]; !ok {
			d.Added = append(d.Added, k)
		}
	}
	for k := range baseline {
		if _, ok := candidate[k]; !ok {
			d.Removed = append(d.Removed, k)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d
}

func setFromMap(m map[string]bool) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k, v := range m {
		if v {
			out[k] = struct{}{}
		}
	}
	return out
}

func setFromSlice(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}
