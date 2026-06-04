package profile

import (
	"context"
	"errors"
	"testing"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// fakeGraph serves a tiny fixed graph: run r1 with one process (pid 10) that
// opened /etc/hostname and invoked openat; plus a DIFFERENT run's process to
// prove run-scoping by _key prefix.
type fakeGraph struct{}

func (fakeGraph) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	switch label {
	case model.LabelRun:
		return []*graphdb.NodeResponse{
			{ID: 1, Labels: []string{model.LabelRun}, Properties: map[string]any{"id": "r1", "target": "/bin/sh", "lossy": false}},
		}, nil
	case model.LabelProcess:
		return []*graphdb.NodeResponse{
			{ID: 10, Labels: []string{model.LabelProcess}, Properties: map[string]any{model.PropKey: model.ProcessKey("r1", 10)}},
			{ID: 99, Labels: []string{model.LabelProcess}, Properties: map[string]any{model.PropKey: model.ProcessKey("OTHER", 99)}},
		}, nil
	}
	return nil, nil
}

func (fakeGraph) Traverse(_ context.Context, startID uint64, _ int) ([]*graphdb.NodeResponse, error) {
	if startID == 10 {
		return []*graphdb.NodeResponse{
			{ID: 20, Labels: []string{model.LabelSyscall}, Properties: map[string]any{"name": "openat"}},
			{ID: 21, Labels: []string{model.LabelFile}, Properties: map[string]any{"path": "/etc/hostname"}},
			{ID: 22, Labels: []string{model.LabelBinary}, Properties: map[string]any{"path": "/bin/sh"}},
			{ID: 23, Labels: []string{model.LabelCapability}, Properties: map[string]any{"name": "CAP_SYS_ADMIN"}},
		}, nil
	}
	// Process 99 belongs to another run and must never be traversed.
	return nil, errUnexpectedTraverse
}

var errUnexpectedTraverse = &traverseErr{}

type traverseErr struct{}

func (*traverseErr) Error() string { return "traversed a process outside the requested run" }

func TestCollect_ScopesToRunAndBucketsByLabel(t *testing.T) {
	b, err := Collect(context.Background(), fakeGraph{}, "r1", 100)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if b.Target != "/bin/sh" || b.Lossy {
		t.Errorf("run metadata wrong: %+v", b)
	}
	if !b.Syscalls["openat"] {
		t.Error("expected openat observed")
	}
	if len(b.Files) != 1 || b.Files[0] != "/etc/hostname" {
		t.Errorf("files = %v, want [/etc/hostname]", b.Files)
	}
	if len(b.Binaries) != 1 || b.Binaries[0] != "/bin/sh" {
		t.Errorf("binaries = %v, want [/bin/sh]", b.Binaries)
	}
	if len(b.Caps) != 1 || b.Caps[0] != "CAP_SYS_ADMIN" {
		t.Errorf("caps = %v, want [CAP_SYS_ADMIN]", b.Caps)
	}
}

func TestCollect_UnknownRunErrors(t *testing.T) {
	if _, err := Collect(context.Background(), fakeGraph{}, "nope", 100); err == nil {
		t.Fatal("expected error for unknown run")
	}
}

// stubGraph is a configurable fake for error/edge-case paths.
type stubGraph struct {
	onLabel    error
	onTraverse error
	runs       []*graphdb.NodeResponse
	procs      []*graphdb.NodeResponse
	neighbors  []*graphdb.NodeResponse
}

func (g stubGraph) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	if g.onLabel != nil {
		return nil, g.onLabel
	}
	switch label {
	case model.LabelRun:
		return g.runs, nil
	case model.LabelProcess:
		return g.procs, nil
	}
	return nil, nil
}

func (g stubGraph) Traverse(_ context.Context, _ uint64, _ int) ([]*graphdb.NodeResponse, error) {
	if g.onTraverse != nil {
		return nil, g.onTraverse
	}
	return g.neighbors, nil
}

func runNode() *graphdb.NodeResponse {
	return &graphdb.NodeResponse{ID: 1, Labels: []string{model.LabelRun}, Properties: map[string]any{"id": "r1", "coverage": "full"}}
}
func procNode() *graphdb.NodeResponse {
	return &graphdb.NodeResponse{ID: 10, Labels: []string{model.LabelProcess}, Properties: map[string]any{model.PropKey: model.ProcessKey("r1", 10)}}
}

func TestCollect_PropagatesErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Collect(context.Background(), stubGraph{onLabel: boom}, "r1", 100); err == nil {
		t.Error("expected NodesByLabel error to propagate")
	}
	g := stubGraph{runs: []*graphdb.NodeResponse{runNode()}, procs: []*graphdb.NodeResponse{procNode()}, onTraverse: boom}
	if _, err := Collect(context.Background(), g, "r1", 100); err == nil {
		t.Error("expected Traverse error to propagate")
	}
}

func TestCollect_ZeroProcessesIsEmptyNotError(t *testing.T) {
	// Run exists, but no process carries this run's _key prefix.
	other := &graphdb.NodeResponse{ID: 99, Labels: []string{model.LabelProcess}, Properties: map[string]any{model.PropKey: model.ProcessKey("OTHER", 99)}}
	g := stubGraph{runs: []*graphdb.NodeResponse{runNode()}, procs: []*graphdb.NodeResponse{other}}
	b, err := Collect(context.Background(), g, "r1", 100)
	if err != nil {
		t.Fatalf("zero processes should not error: %v", err)
	}
	if len(b.Syscalls) != 0 || len(b.Files) != 0 || len(b.Binaries) != 0 {
		t.Errorf("expected empty behavior, got %+v", b)
	}
	if !b.FullCoverage {
		t.Error("coverage flag should still be read from the Run node")
	}
}

func TestCollect_TolerantOfMalformedProperties(t *testing.T) {
	// Neighbors with missing labels, missing properties, and a non-string value
	// must be skipped without panicking.
	g := stubGraph{
		runs:  []*graphdb.NodeResponse{runNode()},
		procs: []*graphdb.NodeResponse{procNode()},
		neighbors: []*graphdb.NodeResponse{
			{ID: 20, Labels: nil, Properties: nil},                                                  // no labels
			{ID: 21, Labels: []string{model.LabelSyscall}, Properties: map[string]any{"name": 123}}, // non-string
			{ID: 22, Labels: []string{model.LabelFile}, Properties: map[string]any{}},               // missing path
		},
	}
	b, err := Collect(context.Background(), g, "r1", 100)
	if err != nil {
		t.Fatalf("malformed properties should be tolerated: %v", err)
	}
	if len(b.Syscalls) != 0 || len(b.Files) != 0 {
		t.Errorf("malformed neighbors should be skipped, got %+v", b)
	}
}
