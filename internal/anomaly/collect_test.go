package anomaly

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// fakeGraph serves NodesByLabel (byLabel) and Traverse (byNode), and seeds a
// whole run's graph (Run + one Process + its syscall/binary/file neighbors) so
// profile.Collect resolves it.
type fakeGraph struct {
	byLabel map[string][]*graphdb.NodeResponse
	byNode  map[uint64][]*graphdb.NodeResponse
	nextID  uint64
}

func newFake() *fakeGraph {
	return &fakeGraph{byLabel: map[string][]*graphdb.NodeResponse{}, byNode: map[uint64][]*graphdb.NodeResponse{}}
}
func (f *fakeGraph) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	return f.byLabel[label], nil
}
func (f *fakeGraph) Traverse(_ context.Context, id uint64, _ int) ([]*graphdb.NodeResponse, error) {
	return f.byNode[id], nil
}
func (f *fakeGraph) id() uint64 { f.nextID++; return f.nextID }

func cov(full bool) string {
	if full {
		return "full"
	}
	return "partial"
}

func (f *fakeGraph) addRun(runID, target string, full, lossy bool, syscalls, binaries, files []string) {
	f.addRunNet(runID, target, full, lossy, syscalls, binaries, files, nil)
}

// addRunNet is addRun plus network endpoints ("ip:port" strings), for tests
// exercising the endpoints dimension.
func (f *fakeGraph) addRunNet(runID, target string, full, lossy bool, syscalls, binaries, files, endpoints []string) {
	f.byLabel[model.LabelRun] = append(f.byLabel[model.LabelRun], &graphdb.NodeResponse{
		ID: f.id(), Labels: []string{model.LabelRun},
		Properties: map[string]any{"id": runID, "target": target, "coverage": cov(full), "lossy": lossy},
	})
	pid := f.id()
	f.byLabel[model.LabelProcess] = append(f.byLabel[model.LabelProcess], &graphdb.NodeResponse{
		ID: pid, Labels: []string{model.LabelProcess},
		Properties: map[string]any{model.PropKey: model.ProcessKey(runID, 1), "pid": float64(1)},
	})
	var nb []*graphdb.NodeResponse
	for _, s := range syscalls {
		nb = append(nb, &graphdb.NodeResponse{ID: f.id(), Labels: []string{model.LabelSyscall}, Properties: map[string]any{"name": s}})
	}
	for _, b := range binaries {
		nb = append(nb, &graphdb.NodeResponse{ID: f.id(), Labels: []string{model.LabelBinary}, Properties: map[string]any{"path": b}})
	}
	for _, fl := range files {
		nb = append(nb, &graphdb.NodeResponse{ID: f.id(), Labels: []string{model.LabelFile}, Properties: map[string]any{"path": fl}})
	}
	for _, ep := range endpoints {
		ip, port, err := net.SplitHostPort(ep)
		if err != nil {
			panic(fmt.Sprintf("addRunNet: bad endpoint %q: %v", ep, err))
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			panic(fmt.Sprintf("addRunNet: bad endpoint port %q: %v", ep, err))
		}
		nb = append(nb, &graphdb.NodeResponse{ID: f.id(), Labels: []string{model.LabelEndpoint}, Properties: map[string]any{"ip": ip, "port": float64(p)}})
	}
	f.byNode[pid] = nb
}

func TestCollect_BuildsBaseline(t *testing.T) {
	f := newFake()
	f.addRun("cand", "/bin/app", true, false, []string{"read", "exec"}, []string{"/bin/app"}, []string{"/etc/conf"})
	f.addRun("b1", "/bin/app", true, false, []string{"read", "exec"}, []string{"/bin/app"}, nil)
	f.addRun("b2", "/bin/app", true, false, []string{"read"}, []string{"/bin/app"}, nil)
	f.addRun("b3", "/bin/app", true, true /*lossy*/, []string{"read", "exec"}, nil, nil)
	f.addRun("other", "/bin/other", true, false, []string{"weird"}, nil, nil)

	cand, base, err := Collect(context.Background(), f, "cand", "", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if cand.RunID != "cand" || !cand.Syscalls["exec"] {
		t.Errorf("candidate not collected: %+v", cand)
	}
	if base.TotalRuns != 2 || base.LossyExcluded != 1 {
		t.Errorf("baseline counts = TotalRuns %d / LossyExcluded %d, want 2 / 1", base.TotalRuns, base.LossyExcluded)
	}
	if base.Syscalls.N != 2 {
		t.Errorf("syscalls N = %d, want 2", base.Syscalls.N)
	}
	if got := base.Syscalls.Support["read"]; got != 1.0 {
		t.Errorf("read support = %.3f, want 1.0", got)
	}
	if got := base.Syscalls.Support["exec"]; got != 0.5 {
		t.Errorf("exec support = %.3f, want 0.5 (in 1 of 2 runs)", got)
	}
	if _, leaked := base.Syscalls.Support["weird"]; leaked {
		t.Error("other-target run leaked into the baseline")
	}
}

func TestCollect_CoverageMismatchZeroesSyscallN(t *testing.T) {
	// Full-coverage candidate, partial-coverage baseline → syscalls/caps not
	// comparable (N=0); binaries/files still comparable.
	f := newFake()
	f.addRun("cand", "/bin/app", true, false, []string{"read"}, []string{"/bin/app"}, nil)
	f.addRun("b1", "/bin/app", false /*partial*/, false, []string{"read"}, []string{"/bin/app"}, nil)

	_, base, err := Collect(context.Background(), f, "cand", "", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if base.Syscalls.N != 0 || base.Caps.N != 0 {
		t.Errorf("coverage mismatch must zero syscalls/caps N, got %d / %d", base.Syscalls.N, base.Caps.N)
	}
	if base.Binaries.N != 1 {
		t.Errorf("binaries should still be comparable across backends, N = %d", base.Binaries.N)
	}
}

func TestCollect_EndpointsComparableAcrossFullCoverageRuns(t *testing.T) {
	// Full-coverage candidate + full-coverage baseline run(s) → endpoints are
	// comparable (N>0), mirroring syscalls/caps.
	f := newFake()
	f.addRunNet("cand", "/bin/app", true, false, []string{"read"}, []string{"/bin/app"}, nil, []string{"1.1.1.1:443"})
	f.addRunNet("b1", "/bin/app", true, false, []string{"read"}, []string{"/bin/app"}, nil, []string{"1.1.1.1:443"})

	_, base, err := Collect(context.Background(), f, "cand", "", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if base.Endpoints.N != 1 {
		t.Errorf("endpoints N = %d, want 1 (one full-coverage baseline run)", base.Endpoints.N)
	}
	if got := base.Endpoints.Support["1.1.1.1:443"]; got != 1.0 {
		t.Errorf("endpoint support = %.3f, want 1.0", got)
	}
}

func TestCollect_SeccompCandidateEndpointsNotComparable(t *testing.T) {
	// A seccomp (partial-coverage) candidate never observes endpoints. Even
	// though the baseline run is full-coverage and did record an endpoint, the
	// endpoints dimension must be N=0 (not comparable) — otherwise a
	// network-blind candidate would make every baseline endpoint look novel
	// the moment the candidate itself contacted anything comparable, or a
	// network-blind baseline run would manufacture false endpoint novelty.
	f := newFake()
	f.addRun("cand", "/bin/app", false /*partial/seccomp*/, false, []string{"read"}, []string{"/bin/app"}, nil)
	f.addRunNet("b1", "/bin/app", true, false, []string{"read"}, []string{"/bin/app"}, nil, []string{"1.1.1.1:443"})

	_, base, err := Collect(context.Background(), f, "cand", "", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if base.Endpoints.N != 0 {
		t.Errorf("a seccomp candidate must not get a comparable endpoints baseline, N = %d, want 0", base.Endpoints.N)
	}
}

func TestCollect_NoBaseline(t *testing.T) {
	f := newFake()
	f.addRun("cand", "/bin/lonely", true, false, []string{"read"}, nil, nil)
	_, base, err := Collect(context.Background(), f, "cand", "", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if base.TotalRuns != 0 {
		t.Errorf("a lone run should yield an empty baseline, got TotalRuns %d", base.TotalRuns)
	}
}

func TestCollect_RunNotFound(t *testing.T) {
	if _, _, err := Collect(context.Background(), newFake(), "missing", "", 500); err == nil {
		t.Error("expected an error for a missing candidate run")
	}
}
