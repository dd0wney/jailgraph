package profile

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// GraphClient is the read surface profile generation needs (consumer-side
// interface, so tests can substitute a fake).
type GraphClient interface {
	NodesByLabel(ctx context.Context, label string, pageLimit int) ([]*graphdb.NodeResponse, error)
	Traverse(ctx context.Context, startID uint64, maxDepth int) ([]*graphdb.NodeResponse, error)
}

// Collect reads the behavior of one run from graphdb.
//
// Strategy (shaped by graphdb's API): Process nodes embed the run id in their
// _key (proc:<runID>:<pid>), so we enumerate the run's processes by label +
// prefix, then depth-1 traverse each to gather the syscalls/files/binaries it
// touched. /traverse is outgoing-only and ignores edge-type filters, so we
// bucket the returned neighbors by label. (NodesByLabel("Process") is an
// unindexed full scan across all runs — fine for now; noted for scale.)
func Collect(ctx context.Context, client GraphClient, runID string, pageLimit int) (Behavior, error) {
	b := Behavior{RunID: runID, Syscalls: map[string]bool{}}

	// Run node: read target + lossy flag, and confirm the run exists.
	runs, err := client.NodesByLabel(ctx, model.LabelRun, pageLimit)
	if err != nil {
		return b, fmt.Errorf("list runs: %w", err)
	}
	found := false
	for _, r := range runs {
		if id, _ := r.Properties["id"].(string); id == runID {
			found = true
			b.Target, _ = r.Properties["target"].(string)
			b.Lossy, _ = r.Properties["lossy"].(bool)
			cov, _ := r.Properties["coverage"].(string)
			b.FullCoverage = cov == "full"
			b.NetCapture, _ = r.Properties["net_capture"].(bool)
			break
		}
	}
	if !found {
		return b, fmt.Errorf("run %q not found", runID)
	}

	// Enumerate this run's process nodes by _key prefix.
	procPrefix := model.ProcessKey(runID, 0)
	procPrefix = procPrefix[:strings.LastIndexByte(procPrefix, ':')+1] // "proc:<runID>:"
	procs, err := client.NodesByLabel(ctx, model.LabelProcess, pageLimit)
	if err != nil {
		return b, fmt.Errorf("list processes: %w", err)
	}

	fileSet := map[string]struct{}{}
	binSet := map[string]struct{}{}
	capSet := map[string]struct{}{}
	nsSet := map[string]struct{}{}
	endpointSet := map[string]struct{}{}
	domainSet := map[string]struct{}{}
	for _, p := range procs {
		key, _ := p.Properties[model.PropKey].(string)
		if !strings.HasPrefix(key, procPrefix) {
			continue
		}
		neighbors, err := client.Traverse(ctx, p.ID, 1)
		if err != nil {
			return b, fmt.Errorf("traverse process %d: %w", p.ID, err)
		}
		for _, n := range neighbors {
			bucket(n, b.Syscalls, fileSet, binSet, capSet, nsSet, endpointSet, domainSet)
		}
	}
	b.Files = sortedKeys(fileSet)
	b.Binaries = sortedKeys(binSet)
	b.Caps = sortedKeys(capSet)
	b.Namespaces = sortedKeys(nsSet)
	b.Endpoints = sortedKeys(endpointSet)
	b.Domains = sortedKeys(domainSet)
	return b, nil
}

// bucket sorts a traversed neighbor into the right behavior set by its label.
func bucket(n *graphdb.NodeResponse, syscalls map[string]bool, files, bins, caps, namespaces, endpoints, domains map[string]struct{}) {
	if len(n.Labels) == 0 {
		return
	}
	switch n.Labels[0] {
	case model.LabelSyscall:
		if name, _ := n.Properties["name"].(string); name != "" {
			syscalls[name] = true
		}
	case model.LabelFile:
		if path, _ := n.Properties["path"].(string); path != "" {
			files[path] = struct{}{}
		}
	case model.LabelBinary:
		if path, _ := n.Properties["path"].(string); path != "" {
			bins[path] = struct{}{}
		}
	case model.LabelCapability:
		if name, _ := n.Properties["name"].(string); name != "" {
			caps[name] = struct{}{}
		}
	case model.LabelNamespace:
		if t, _ := n.Properties["type"].(string); t != "" {
			namespaces[t] = struct{}{}
		}
	case model.LabelEndpoint:
		ip, _ := n.Properties["ip"].(string)
		port := toPort(n.Properties["port"])
		if ip != "" {
			endpoints[ip+":"+strconv.Itoa(int(port))] = struct{}{}
		}
	case model.LabelDomain:
		if name, _ := n.Properties["name"].(string); name != "" {
			domains[name] = struct{}{}
		}
	}
}

// toPort coerces a graph port property (float64 from JSON, or a native int) to
// uint16.
func toPort(v any) uint16 {
	switch x := v.(type) {
	case float64:
		return uint16(x)
	case int:
		return uint16(x)
	case uint16:
		return x
	default:
		return 0
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out) // deterministic output
	return out
}
