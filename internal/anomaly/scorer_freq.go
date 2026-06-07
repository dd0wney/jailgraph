package anomaly

import (
	"fmt"
	"sort"

	"github.com/dd0wney/jailgraph/internal/audit"
	"github.com/dd0wney/jailgraph/internal/profile"
)

// Scoring knobs (tunable). RareSupport is the support below which a present item
// is "rare" rather than common (meaningful only at N >~ 1/RareSupport runs).
// MinConfidentN is the baseline size below which a dimension is low-confidence:
// severity is capped and only NOVEL items are distinguishable.
var (
	RareSupport   = 0.05
	MinConfidentN = 5
)

// FrequencyScorer scores by per-item support: an item the population never showed
// (support 0) is NOVEL (strongest); an item below RareSupport is RARE (one level
// down). Severity is by dimension (syscall novelty High, binary/cap Medium, file
// Info-and-never-drives), capped on a low-confidence (small-N) baseline.
type FrequencyScorer struct{}

func (FrequencyScorer) Score(base Baseline, cand profile.Behavior) []Finding {
	// Syscalls: only the security-relevant (gateable) set drives novelty. The full
	// eBPF syscall set includes nondeterministic hot-path/signal syscalls (futex,
	// tgkill, sched_yield, restart_syscall) that differ between *benign* runs of
	// the same binary — scoring those would flap exit 1 on scheduler jitter. This
	// also makes eBPF and seccomp candidates consistent (seccomp only ever sees
	// the gateable set). Non-gateable novelty is summarized, not individually
	// scored — and never silently dropped.
	gateable, otherNovel := splitSyscalls(mapKeys(cand.Syscalls), base.Syscalls)
	// Exec'd binaries also surface as File nodes (opened to exec); score them once,
	// in the binary dimension only.
	files := filterOut(cand.Files, toSet(cand.Binaries))

	dims := []struct {
		name     string
		dim      DimBaseline
		items    []string
		novelSev Severity
	}{
		{"syscall", base.Syscalls, gateable, SevHigh},
		{"binary", base.Binaries, cand.Binaries, SevMedium},
		{"cap", base.Caps, cand.Caps, SevMedium},
		{"file", base.Files, normalizeAll(files), SevInfo},
	}

	var out []Finding
	if base.Syscalls.N > 0 && otherNovel > 0 {
		out = append(out, Finding{"syscall", SevInfo,
			fmt.Sprintf("%d non-security syscall(s) novel — not scored", otherNovel),
			"the full syscall set includes hot-path/signal syscalls that drift between benign runs; only the security-relevant (gateable) set drives the verdict",
			"informational — not an anomaly on its own"})
	}
	for _, d := range dims {
		// N==0 → not comparable (coverage mismatch or the population never observed
		// this dimension). Say so explicitly; a "missing" item here is a blinder,
		// not an anomaly. Only worth noting when the candidate actually has items,
		// or for the coverage-sensitive syscall/cap dimensions.
		if d.dim.N == 0 {
			if len(d.items) > 0 || d.name == "syscall" || d.name == "cap" {
				out = append(out, Finding{"coverage", SevInfo,
					"cannot score " + d.name + "s — no comparable baseline",
					"the baseline observed no comparable " + d.name + " data (coverage mismatch or dimension absent); not scored",
					"compare against a baseline traced with the same backend (eBPF for syscalls/caps)"})
			}
			continue
		}

		novelSev := d.novelSev
		if d.dim.N < MinConfidentN {
			novelSev = bumpDown(novelSev) // cap severity on a thin baseline
			out = append(out, Finding{"coverage", SevInfo,
				fmt.Sprintf("low-confidence %s baseline (only %d run(s))", d.name, d.dim.N),
				"with few baseline runs only NOVEL items are distinguishable and severity is capped",
				"accumulate more confirmed-normal runs of this target to raise confidence"})
		}

		for _, item := range dedup(d.items) {
			support, ok := d.dim.Support[item]
			switch {
			case !ok || support == 0: // NOVEL
				out = append(out, Finding{d.name, novelSev,
					"novel " + d.name + ": " + item,
					fmt.Sprintf("seen in 0/%d baseline runs (novel)", d.dim.N),
					"investigate — behaviour this target never showed before"})
			case support < RareSupport: // RARE
				out = append(out, Finding{d.name, bumpDown(novelSev),
					"rare " + d.name + ": " + item,
					fmt.Sprintf("seen in %.0f%% of %d baseline runs (rare)", support*100, d.dim.N),
					"review — uncommon for this target"})
			}
		}
	}
	return out
}

// bumpDown shifts a severity one level toward Info (Critical→High→Medium→Info).
func bumpDown(s Severity) Severity {
	switch s {
	case SevCritical:
		return SevHigh
	case SevHigh:
		return SevMedium
	case SevMedium:
		return SevInfo
	default:
		return SevInfo
	}
}

// gateableSet is profile.GateableSyscalls as a lookup — the security-relevant
// syscalls whose novelty is meaningful (not hot-path noise).
var gateableSet = func() map[string]bool {
	m := make(map[string]bool, len(profile.GateableSyscalls))
	for _, s := range profile.GateableSyscalls {
		m[s] = true
	}
	return m
}()

// splitSyscalls partitions a candidate's syscalls into the gateable ones (scored
// for novelty) and a count of NON-gateable novel ones (summarized, not scored).
func splitSyscalls(cand []string, dim DimBaseline) (gateable []string, otherNovel int) {
	for _, s := range cand {
		switch {
		case gateableSet[s]:
			gateable = append(gateable, s)
		case dim.Support[s] == 0:
			otherNovel++
		}
	}
	return gateable, otherNovel
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// filterOut returns the items not present in drop.
func filterOut(items []string, drop map[string]bool) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !drop[it] {
			out = append(out, it)
		}
	}
	return out
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func normalizeAll(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, audit.NormalizePath(p))
	}
	return out
}

// dedup returns the unique items, sorted for deterministic finding order.
func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	var out []string
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	sort.Strings(out)
	return out
}
