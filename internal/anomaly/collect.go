package anomaly

import (
	"context"
	"fmt"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
	"github.com/dd0wney/jailgraph/internal/profile"
)

// GraphClient is the read surface Collect needs (same as profile's).
type GraphClient interface {
	NodesByLabel(ctx context.Context, label string, pageLimit int) ([]*graphdb.NodeResponse, error)
	Traverse(ctx context.Context, startID uint64, maxDepth int) ([]*graphdb.NodeResponse, error)
}

// Collect reads the candidate run's behaviour and builds the population Baseline
// from the other runs of the same target (or baselineTarget, if given). The
// per-dimension N is coverage-comparable to the candidate (syscalls/caps only
// across same-coverage-class runs; binaries/files across all non-lossy runs),
// so the Scorer never sees false novelty from a backend that simply couldn't
// observe a dimension.
func Collect(ctx context.Context, client GraphClient, candidateRunID, baselineTarget string, pageLimit int) (profile.Behavior, Baseline, error) {
	var cand profile.Behavior

	runs, err := client.NodesByLabel(ctx, model.LabelRun, pageLimit)
	if err != nil {
		return cand, Baseline{}, fmt.Errorf("list runs: %w", err)
	}

	candTarget, found := "", false
	for _, r := range runs {
		if id, _ := r.Properties["id"].(string); id == candidateRunID {
			candTarget, _ = r.Properties["target"].(string)
			found = true
			break
		}
	}
	if !found {
		return cand, Baseline{}, fmt.Errorf("run %q not found", candidateRunID)
	}
	target := baselineTarget
	if target == "" {
		target = candTarget
	}

	cand, err = profile.Collect(ctx, client, candidateRunID, pageLimit)
	if err != nil {
		return cand, Baseline{}, fmt.Errorf("collect candidate run: %w", err)
	}

	var population []profile.Behavior
	lossyExcluded := 0
	for _, r := range runs {
		id, _ := r.Properties["id"].(string)
		tgt, _ := r.Properties["target"].(string)
		if id == candidateRunID || tgt != target {
			continue
		}
		b, err := profile.Collect(ctx, client, id, pageLimit)
		if err != nil {
			return cand, Baseline{}, fmt.Errorf("collect baseline run %s: %w", id, err)
		}
		if b.Lossy {
			lossyExcluded++ // a lossy run's absence of an item isn't evidence
			continue
		}
		population = append(population, b)
	}

	return cand, buildBaseline(target, cand.FullCoverage, population, lossyExcluded), nil
}

func buildBaseline(target string, candFull bool, pop []profile.Behavior, lossyExcluded int) Baseline {
	// Syscalls/caps are only comparable across the candidate's coverage class.
	sameCov := filterBeh(pop, func(b profile.Behavior) bool { return b.FullCoverage == candFull })
	var capRuns []profile.Behavior
	if candFull { // caps are observed only on full-coverage (eBPF) runs
		capRuns = filterBeh(pop, func(b profile.Behavior) bool { return b.FullCoverage })
	}
	// Endpoints are observed only on network-capable (full-coverage/eBPF) runs.
	// Compare only within that class, mirroring syscalls/caps, so a network-blind
	// baseline run never manufactures false endpoint novelty.
	var netRuns []profile.Behavior
	if candFull {
		netRuns = filterBeh(pop, func(b profile.Behavior) bool { return b.FullCoverage })
	}
	return Baseline{
		Target:                target,
		Syscalls:              buildDim(sameCov, func(b profile.Behavior) []string { return mapKeys(b.Syscalls) }),
		Caps:                  buildDim(capRuns, func(b profile.Behavior) []string { return b.Caps }),
		Binaries:              buildDim(pop, func(b profile.Behavior) []string { return b.Binaries }),
		Files:                 buildDim(pop, func(b profile.Behavior) []string { return normalizeAll(b.Files) }),
		Endpoints:             buildDim(netRuns, func(b profile.Behavior) []string { return b.Endpoints }),
		TotalRuns:             len(pop),
		LossyExcluded:         lossyExcluded,
		CandidateFullCoverage: candFull,
	}
}

func filterBeh(in []profile.Behavior, keep func(profile.Behavior) bool) []profile.Behavior {
	var out []profile.Behavior
	for _, b := range in {
		if keep(b) {
			out = append(out, b)
		}
	}
	return out
}

// buildDim tallies how many of the given runs each item appeared in → support.
func buildDim(behs []profile.Behavior, items func(profile.Behavior) []string) DimBaseline {
	support := map[string]float64{}
	n := len(behs)
	if n == 0 {
		return DimBaseline{Support: support, N: 0}
	}
	counts := map[string]int{}
	for _, b := range behs {
		seen := map[string]struct{}{}
		for _, it := range items(b) {
			if _, ok := seen[it]; ok {
				continue
			}
			seen[it] = struct{}{}
			counts[it]++
		}
	}
	for it, c := range counts {
		support[it] = float64(c) / float64(n)
	}
	return DimBaseline{Support: support, N: n}
}
