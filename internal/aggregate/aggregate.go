// Package aggregate collapses the per-event graph explosion (from
// internal/model) into a deduplicated, batch-ready graph: one node per natural
// key, one edge per (type, from, to) identity, with repeated INVOKED edges
// folded into a single edge carrying a summed count.
//
// Aggregation happens before ingestion both to honour graphdb's 1000-item batch
// limit (a tight loop calling write() millions of times would otherwise emit
// millions of duplicate edges) and to turn raw syscall frequency into the
// count property a generated profile will reason about.
package aggregate

import (
	"sort"

	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/model"
)

// Builder accumulates events into a deduplicated graph for one run.
type Builder struct {
	runID string
	nodes map[string]model.Node
	edges map[string]model.Edge
}

// New returns a Builder for the given run id.
func New(runID string) *Builder {
	return &Builder{
		runID: runID,
		nodes: make(map[string]model.Node),
		edges: make(map[string]model.Edge),
	}
}

// Add folds one event into the accumulated graph.
func (b *Builder) Add(e collector.BehaviorEvent) {
	nodes, edges := model.EventToGraph(b.runID, e)
	for _, n := range nodes {
		b.mergeNode(n)
	}
	for _, ed := range edges {
		b.mergeEdge(ed)
	}
}

func (b *Builder) mergeNode(n model.Node) {
	existing, ok := b.nodes[n.Key]
	if !ok {
		b.nodes[n.Key] = n
		return
	}
	// Same node seen again: fill in properties that the first sighting lacked.
	// Later non-empty values win so a Process first seen via a bare syscall
	// (no exe) is enriched when its exec is later observed.
	for k, v := range n.Properties {
		if isEmpty(existing.Properties[k]) && !isEmpty(v) {
			existing.Properties[k] = v
		}
	}
	b.nodes[n.Key] = existing
}

func (b *Builder) mergeEdge(e model.Edge) {
	id := e.Type + "\x00" + e.FromKey + "\x00" + e.ToKey
	existing, ok := b.edges[id]
	if !ok {
		b.edges[id] = e
		return
	}
	// INVOKED edges accumulate; other structural edges are idempotent (dedup).
	if e.Type == model.EdgeInvoked {
		existing.Properties["count"] = toInt(existing.Properties["count"]) + toInt(e.Properties["count"])
		b.edges[id] = existing
	}
}

// Nodes returns the deduplicated nodes in deterministic (key-sorted) order so
// batches are reproducible and tests are stable.
func (b *Builder) Nodes() []model.Node {
	out := make([]model.Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Edges returns the deduplicated edges in deterministic order.
func (b *Builder) Edges() []model.Edge {
	out := make([]model.Edge, 0, len(b.edges))
	for _, e := range b.edges {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].FromKey != out[j].FromKey {
			return out[i].FromKey < out[j].FromKey
		}
		return out[i].ToKey < out[j].ToKey
	})
	return out
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case int:
		return x == 0
	case int32:
		return x == 0
	case uint32:
		return x == 0
	case uint64:
		return x == 0
	default:
		return false
	}
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	default:
		return 0
	}
}
