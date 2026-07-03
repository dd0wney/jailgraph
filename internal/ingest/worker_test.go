package ingest

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/aggregate"
	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
	"github.com/dd0wney/jailgraph/internal/run"
)

// fakeClient simulates graphdb's partial-success, out-of-order contract.
type fakeClient struct {
	nextID uint64
	// dropKeys are node _key values the server "rejects" (not returned).
	dropKeys map[string]bool
	// existing seeds NodesByLabel to simulate a prior run's shared nodes.
	existing map[string][]*graphdb.NodeResponse
	// reverse, when true, returns batch responses in reverse order.
	reverse bool

	createdNodes []graphdb.NodeRequest
	createdEdges []graphdb.EdgeRequest
}

func (f *fakeClient) id() uint64 { f.nextID++; return f.nextID }

func (f *fakeClient) CreateNode(_ context.Context, req graphdb.NodeRequest) (*graphdb.NodeResponse, error) {
	f.createdNodes = append(f.createdNodes, req)
	return &graphdb.NodeResponse{ID: f.id(), Labels: req.Labels, Properties: req.Properties}, nil
}

func (f *fakeClient) BatchNodes(_ context.Context, reqs []graphdb.NodeRequest) ([]*graphdb.NodeResponse, error) {
	var out []*graphdb.NodeResponse
	for _, r := range reqs {
		key, _ := r.Properties[model.PropKey].(string)
		if f.dropKeys[key] {
			continue // simulate server-side validation failure
		}
		f.createdNodes = append(f.createdNodes, r)
		out = append(out, &graphdb.NodeResponse{ID: f.id(), Labels: r.Labels, Properties: r.Properties})
	}
	if f.reverse {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}

func (f *fakeClient) BatchEdges(_ context.Context, reqs []graphdb.EdgeRequest) ([]*graphdb.EdgeResponse, error) {
	var out []*graphdb.EdgeResponse
	for _, r := range reqs {
		f.createdEdges = append(f.createdEdges, r)
		out = append(out, &graphdb.EdgeResponse{ID: f.id(), FromNodeID: r.FromNodeID, ToNodeID: r.ToNodeID, Type: r.Type})
	}
	return out, nil
}

func (f *fakeClient) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	return f.existing[label], nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func buildSampleGraph(runID string) *aggregate.Builder {
	b := aggregate.New(runID)
	// sh execs, opens a file, makes a syscall twice.
	b.Add(collector.BehaviorEvent{Kind: collector.EventExec, PID: 10, Exe: "/bin/sh", BinSHA256: "sh1", SyscallNr: 59, SyscallName: "execve"})
	b.Add(collector.BehaviorEvent{Kind: collector.EventOpen, PID: 10, Path: "/etc/hostname", OpenMode: "r", SyscallNr: 257, SyscallName: "openat"})
	b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 257, SyscallName: "openat"})
	return b
}

func TestFlush_CreatesRunNodeFirstSoPartOfResolves(t *testing.T) {
	f := &fakeClient{}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/sh", time.Unix(0, 0))

	stats, err := w.Flush(context.Background(), sess, buildSampleGraph(sess.ID))
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// The Run node must have been created via CreateNode (first), and the
	// PART_OF edge must NOT be quarantined.
	if _, ok := w.cache.Get(model.RunKey(sess.ID)); !ok {
		t.Error("Run node not cached")
	}
	var partOf int
	for _, e := range f.createdEdges {
		if e.Type == model.EdgePartOf {
			partOf++
		}
	}
	if partOf != 1 {
		t.Errorf("PART_OF edges created = %d, want 1 (Run must exist first)", partOf)
	}
	if stats.EdgesQuarantined != 0 {
		t.Errorf("quarantined %d edges, want 0", stats.EdgesQuarantined)
	}
}

func TestFlush_FileActivityNodeLandsPerRunWithPartOf(t *testing.T) {
	f := &fakeClient{}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/sh", time.Unix(0, 0))

	b := aggregate.New(sess.ID)
	b.Add(collector.BehaviorEvent{
		Kind: collector.EventFileActivity, Path: "/data/doc.txt",
		WriteCount: 9, Bytes: 8192, RenameCount: 1, UnlinkCount: 0,
	})

	stats, err := w.Flush(context.Background(), sess, b)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// The FileActivity node was created carrying its stats...
	var fa *graphdb.NodeRequest
	for i := range f.createdNodes {
		if len(f.createdNodes[i].Labels) == 1 && f.createdNodes[i].Labels[0] == model.LabelFileActivity {
			fa = &f.createdNodes[i]
		}
	}
	if fa == nil {
		t.Fatal("FileActivity node not created")
	}
	if fa.Properties["write_count"] != int64(9) || fa.Properties["bytes"] != int64(8192) || fa.Properties["rename_count"] != int64(1) {
		t.Errorf("FileActivity props = %+v", fa.Properties)
	}
	// ...and its PART_OF edge to the Run resolved (Run created first, not quarantined).
	if stats.EdgesQuarantined != 0 {
		t.Errorf("quarantined %d edges, want 0", stats.EdgesQuarantined)
	}
	var partOf int
	for _, e := range f.createdEdges {
		if e.Type == model.EdgePartOf {
			partOf++
		}
	}
	if partOf != 1 {
		t.Errorf("PART_OF edges = %d, want 1", partOf)
	}
}

func TestFlush_ReconcilesOutOfOrderResponse(t *testing.T) {
	f := &fakeClient{reverse: true}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/sh", time.Unix(0, 0))

	stats, err := w.Flush(context.Background(), sess, buildSampleGraph(sess.ID))
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Even with reversed responses, every edge endpoint must resolve.
	if stats.EdgesQuarantined != 0 || stats.EdgesDropped != 0 {
		t.Errorf("reconciliation failed under reversed order: %+v", stats)
	}
	if stats.NodesCreated == 0 || stats.EdgesCreated == 0 {
		t.Errorf("expected nodes and edges created, got %+v", stats)
	}
}

func TestFlush_DeduplicatesAgainstPriorRun(t *testing.T) {
	// Simulate /bin/sh's Binary node already existing from a prior run.
	binKey := model.BinaryKey("sh1", "/bin/sh")
	f := &fakeClient{
		existing: map[string][]*graphdb.NodeResponse{
			model.LabelBinary: {{ID: 999, Properties: map[string]any{model.PropKey: binKey}}},
		},
	}
	w := NewWorker(f, quietLogger(), WithCacheRebuild(true))
	sess := run.New("/bin/sh", time.Unix(0, 0))

	stats, err := w.Flush(context.Background(), sess, buildSampleGraph(sess.ID))
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if stats.NodesDeduped < 1 {
		t.Errorf("expected the prior Binary node to be deduped, stats=%+v", stats)
	}
	// The EXEC edge must still resolve to the cached prior id (999).
	id, ok := w.cache.Get(binKey)
	if !ok || id != 999 {
		t.Errorf("binary key resolved to %d/%v, want 999/true", id, ok)
	}
}

func TestFlush_EmptyGraph(t *testing.T) {
	// An empty run still writes the Run node, no nodes/edges, no error.
	f := &fakeClient{}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/true", time.Unix(0, 0))
	stats, err := w.Flush(context.Background(), sess, aggregate.New(sess.ID))
	if err != nil {
		t.Fatalf("Flush empty: %v", err)
	}
	if stats.NodesCreated != 0 || stats.EdgesCreated != 0 || stats.EdgesQuarantined != 0 {
		t.Errorf("empty graph stats = %+v, want all zero", stats)
	}
	if _, ok := w.cache.Get(model.RunKey(sess.ID)); !ok {
		t.Error("Run node should still be created for an empty graph")
	}
}

func TestCreateRunNode_WritesNetCaptureProperty(t *testing.T) {
	f := &fakeClient{}
	w := NewWorker(f, quietLogger())
	sess := run.New("/usr/bin/curl", time.Unix(0, 0))
	sess.NetCapture = true

	if err := w.createRunNode(context.Background(), sess); err != nil {
		t.Fatalf("createRunNode: %v", err)
	}

	var runNode *graphdb.NodeRequest
	for i := range f.createdNodes {
		if len(f.createdNodes[i].Labels) == 1 && f.createdNodes[i].Labels[0] == model.LabelRun {
			runNode = &f.createdNodes[i]
		}
	}
	if runNode == nil {
		t.Fatal("Run node not created")
	}
	if nc, ok := runNode.Properties["net_capture"].(bool); !ok || !nc {
		t.Errorf("net_capture property = %v, want true", runNode.Properties["net_capture"])
	}
}

func TestCreateRunNode_NetCaptureDefaultsFalse(t *testing.T) {
	// seccomp/esf/replay sessions never set NetCapture; the Run node must record
	// that explicitly (false), not omit the property.
	f := &fakeClient{}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/sh", time.Unix(0, 0))

	if err := w.createRunNode(context.Background(), sess); err != nil {
		t.Fatalf("createRunNode: %v", err)
	}

	var runNode *graphdb.NodeRequest
	for i := range f.createdNodes {
		if len(f.createdNodes[i].Labels) == 1 && f.createdNodes[i].Labels[0] == model.LabelRun {
			runNode = &f.createdNodes[i]
		}
	}
	if runNode == nil {
		t.Fatal("Run node not created")
	}
	if nc, ok := runNode.Properties["net_capture"].(bool); !ok || nc {
		t.Errorf("net_capture property = %v, want false (present, not true)", runNode.Properties["net_capture"])
	}
}

func TestFlush_ChunkingAcrossMultipleBatches(t *testing.T) {
	// batchSize 2 with a sample graph (>2 nodes) must create every node across
	// multiple batches and resolve all edges.
	f := &fakeClient{}
	w := NewWorker(f, quietLogger(), WithBatchSize(2))
	sess := run.New("/bin/sh", time.Unix(0, 0))
	stats, err := w.Flush(context.Background(), sess, buildSampleGraph(sess.ID))
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if stats.NodesDropped != 0 || stats.EdgesQuarantined != 0 || stats.EdgesDropped != 0 {
		t.Errorf("chunked flush lost items: %+v", stats)
	}
	if stats.NodesCreated < 3 || stats.EdgesCreated < 3 {
		t.Errorf("expected the full sample created across batches, got %+v", stats)
	}
}

func TestChunked(t *testing.T) {
	cases := []struct {
		n, size, wantChunks int
	}{
		{0, 5, 0},  // empty
		{4, 2, 2},  // exact multiple
		{5, 2, 3},  // remainder
		{3, 10, 1}, // size >= len
		{3, 1, 3},  // size 1
		{3, 0, 1},  // size 0 -> single chunk (defensive, no infinite loop)
		{3, -1, 1}, // negative -> single chunk
	}
	for _, c := range cases {
		in := make([]int, c.n)
		got := chunked(in, c.size)
		if len(got) != c.wantChunks {
			t.Errorf("chunked(len=%d,size=%d) = %d chunks, want %d", c.n, c.size, len(got), c.wantChunks)
		}
		var total int
		for _, ch := range got {
			total += len(ch)
		}
		if total != c.n {
			t.Errorf("chunked(len=%d,size=%d) dropped items: total=%d", c.n, c.size, total)
		}
	}
}

func TestFlush_QuarantinesEdgeWithDroppedEndpoint(t *testing.T) {
	// Drop the File node; the OPENED edge to it must be quarantined, not sent.
	fileKey := model.FileKey("/etc/hostname")
	f := &fakeClient{dropKeys: map[string]bool{fileKey: true}}
	w := NewWorker(f, quietLogger())
	sess := run.New("/bin/sh", time.Unix(0, 0))

	stats, err := w.Flush(context.Background(), sess, buildSampleGraph(sess.ID))
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if stats.NodesDropped != 1 {
		t.Errorf("nodes dropped = %d, want 1", stats.NodesDropped)
	}
	if stats.EdgesQuarantined != 1 {
		t.Errorf("edges quarantined = %d, want 1 (the OPENED edge)", stats.EdgesQuarantined)
	}
	for _, e := range f.createdEdges {
		if e.Type == model.EdgeOpened {
			t.Error("OPENED edge to a dropped node should not have been sent")
		}
	}
}
