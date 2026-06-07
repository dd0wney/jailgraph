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
	dims := []struct {
		name     string
		dim      DimBaseline
		items    []string
		novelSev Severity
	}{
		{"syscall", base.Syscalls, mapKeys(cand.Syscalls), SevHigh},
		{"binary", base.Binaries, cand.Binaries, SevMedium},
		{"cap", base.Caps, cand.Caps, SevMedium},
		{"file", base.Files, normalizeAll(cand.Files), SevInfo},
	}

	var out []Finding
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
