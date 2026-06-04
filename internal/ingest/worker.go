package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/dd0wney/jailgraph/internal/aggregate"
	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
	"github.com/dd0wney/jailgraph/internal/run"
)

// DefaultBatchSize is graphdb's hard per-batch maximum.
const DefaultBatchSize = 1000

// sharedLabels are content-identified node labels shared across runs. The cache
// is rebuilt from the server for exactly these (Process/Run are per-run and
// must never be deduplicated against earlier runs).
var sharedLabels = []string{
	model.LabelBinary, model.LabelSyscall, model.LabelFile,
	model.LabelCapability, model.LabelNamespace,
}

// Stats summarises a flush. Every non-created item is accounted for here and in
// the logs — nothing is dropped silently.
type Stats struct {
	NodesCreated     int
	NodesDeduped     int // already in cache, not sent
	NodesDropped     int // sent but not returned (failed server-side validation)
	EdgesCreated     int
	EdgesQuarantined int // endpoint key unresolved (its node was dropped/missing)
	EdgesDropped     int // sent but not returned
}

// Worker writes an aggregated behavior graph to graphdb using two phases
// (nodes, then edges) so edges can reference the ids assigned to their endpoint
// nodes.
type Worker struct {
	client    GraphClient
	cache     *IDCache
	log       *slog.Logger
	batchSize int
	// rebuildCache, when true, repopulates the cache from the server before
	// writing — the cross-run dedup guarantee. Disabled in unit tests.
	rebuildCache bool
}

// Option configures a Worker.
type Option func(*Worker)

// WithBatchSize overrides the batch size (capped at DefaultBatchSize).
func WithBatchSize(n int) Option {
	return func(w *Worker) {
		if n > 0 && n <= DefaultBatchSize {
			w.batchSize = n
		}
	}
}

// WithCacheRebuild enables rebuilding the id-cache from the server before flush.
func WithCacheRebuild(enabled bool) Option {
	return func(w *Worker) { w.rebuildCache = enabled }
}

// NewWorker builds a Worker.
func NewWorker(client GraphClient, log *slog.Logger, opts ...Option) *Worker {
	w := &Worker{
		client:    client,
		cache:     NewIDCache(),
		log:       log,
		batchSize: DefaultBatchSize,
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Flush writes the Run node, then the aggregated nodes, then the edges. It
// returns stats and the first fatal error encountered (rate-limit/transport
// errors are retried inside the client; a returned error means the batch could
// not be written at all).
//
// Invariant: b MUST have been built with aggregate.New(sess.ID). The PART_OF
// edges the aggregator emits reference RunKey(sess.ID); if the builder used a
// different run id, those edges (and the whole process tree's anchoring to the
// run) would quarantine. The CLI guarantees this by creating the session first
// and threading sess.ID into the aggregator.
func (w *Worker) Flush(ctx context.Context, sess *run.Session, b *aggregate.Builder) (Stats, error) {
	var stats Stats

	if w.rebuildCache {
		if err := w.cache.Rebuild(ctx, w.client, sharedLabels, w.batchSize); err != nil {
			return stats, fmt.Errorf("rebuild id-cache: %w", err)
		}
		w.log.Info("id-cache rebuilt from server", "keys", w.cache.Len())
	}

	// Phase 0: the Run node must exist before any PART_OF edge references it.
	if err := w.createRunNode(ctx, sess); err != nil {
		return stats, fmt.Errorf("create run node: %w", err)
	}

	// Phase A: nodes.
	if err := w.flushNodes(ctx, b.Nodes(), &stats); err != nil {
		return stats, err
	}
	// Phase B: edges.
	if err := w.flushEdges(ctx, b.Edges(), &stats); err != nil {
		return stats, err
	}

	w.log.Info("flush complete",
		"nodes_created", stats.NodesCreated, "nodes_deduped", stats.NodesDeduped,
		"nodes_dropped", stats.NodesDropped, "edges_created", stats.EdgesCreated,
		"edges_quarantined", stats.EdgesQuarantined, "edges_dropped", stats.EdgesDropped,
		"lossy", sess.Lossy)
	return stats, nil
}

func (w *Worker) createRunNode(ctx context.Context, sess *run.Session) error {
	key := model.RunKey(sess.ID)
	coverage := sess.Coverage
	if coverage == "" {
		coverage = run.CoveragePartial // safe default
	}
	props := map[string]any{
		"id":          sess.ID,
		"target":      sess.Target,
		"started_at":  sess.StartedAt.UTC().Format(time.RFC3339Nano),
		"lossy":       sess.Lossy,
		"coverage":    coverage,
		model.PropKey: key,
	}
	if !sess.EndedAt.IsZero() {
		props["ended_at"] = sess.EndedAt.UTC().Format(time.RFC3339Nano)
	}
	for kind, n := range sess.Dropped {
		props["dropped_"+kind] = n
	}
	resp, err := w.client.CreateNode(ctx, graphdb.NodeRequest{Labels: []string{model.LabelRun}, Properties: props})
	if err != nil {
		return err
	}
	w.cache.Put(key, resp.ID)
	return nil
}

func (w *Worker) flushNodes(ctx context.Context, nodes []model.Node, stats *Stats) error {
	// Dedup against the cache; only uncached keys are sent.
	var pending []model.Node
	for _, n := range nodes {
		if _, ok := w.cache.Get(n.Key); ok {
			stats.NodesDeduped++
			continue
		}
		pending = append(pending, n)
	}

	for _, chunk := range chunked(pending, w.batchSize) {
		reqs := make([]graphdb.NodeRequest, len(chunk))
		sent := make(map[string]struct{}, len(chunk))
		for i, n := range chunk {
			reqs[i] = graphdb.NodeRequest{Labels: n.Labels, Properties: n.Properties}
			sent[n.Key] = struct{}{}
		}
		created, err := w.client.BatchNodes(ctx, reqs)
		if err != nil {
			return fmt.Errorf("batch nodes: %w", err)
		}
		// Reconcile by the echoed _key (response is partial + out-of-order).
		for _, c := range created {
			key, _ := c.Properties[model.PropKey].(string)
			if key == "" {
				w.log.Warn("created node missing _key property; cannot reconcile", "id", c.ID)
				continue
			}
			w.cache.Put(key, c.ID)
			delete(sent, key)
			stats.NodesCreated++
		}
		// Whatever remains in `sent` was dropped server-side. This is
		// deterministic (failed validation), so we log identity and do NOT
		// re-enqueue.
		for key := range sent {
			stats.NodesDropped++
			w.log.Error("node dropped by graphdb (failed validation); not retried", "key", key)
		}
	}
	return nil
}

func (w *Worker) flushEdges(ctx context.Context, edges []model.Edge, stats *Stats) error {
	// Resolve endpoints; quarantine edges whose endpoint node was never created.
	type resolved struct {
		from, to uint64
		edge     model.Edge
	}
	var pending []resolved
	for _, e := range edges {
		from, okF := w.cache.Get(e.FromKey)
		to, okT := w.cache.Get(e.ToKey)
		if !okF || !okT {
			stats.EdgesQuarantined++
			w.log.Warn("edge quarantined: unresolved endpoint",
				"type", e.Type, "from", e.FromKey, "to", e.ToKey,
				"from_resolved", okF, "to_resolved", okT)
			continue
		}
		pending = append(pending, resolved{from: from, to: to, edge: e})
	}

	for _, chunk := range chunked(pending, w.batchSize) {
		reqs := make([]graphdb.EdgeRequest, len(chunk))
		// Sent set keyed by (from,to,type) — edges have no natural key; this
		// tuple is unique per batch (the aggregator deduped on it).
		sent := make(map[edgeTuple]struct{}, len(chunk))
		for i, r := range chunk {
			reqs[i] = graphdb.EdgeRequest{
				FromNodeID: r.from, ToNodeID: r.to, Type: r.edge.Type,
				Properties: r.edge.Properties, Weight: 1,
			}
			sent[edgeTuple{r.from, r.to, r.edge.Type}] = struct{}{}
		}
		created, err := w.client.BatchEdges(ctx, reqs)
		if err != nil {
			return fmt.Errorf("batch edges: %w", err)
		}
		for _, c := range created {
			delete(sent, edgeTuple{c.FromNodeID, c.ToNodeID, c.Type})
			stats.EdgesCreated++
		}
		for tup := range sent {
			stats.EdgesDropped++
			w.log.Error("edge dropped by graphdb (failed validation); not retried",
				"type", tup.typ, "from", tup.from, "to", tup.to)
		}
	}
	return nil
}

type edgeTuple struct {
	from, to uint64
	typ      string
}

func chunked[T any](in []T, size int) [][]T {
	if size <= 0 {
		size = len(in) // defensive: never loop forever on a non-positive size
	}
	var out [][]T
	for i := 0; i < len(in); i += size {
		end := min(i+size, len(in))
		out = append(out, in[i:end])
	}
	return out
}
