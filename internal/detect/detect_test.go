package detect

import (
	"context"
	"strings"
	"testing"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// fakeGraph serves NodesByLabel from seeded slices — the detector's only read.
type fakeGraph struct {
	byLabel map[string][]*graphdb.NodeResponse
}

func (f *fakeGraph) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	return f.byLabel[label], nil
}

// faNode builds a FileActivity NodeResponse with float64 props — the shape
// graphdb returns on read-back (JSON numbers unmarshal to float64). The whole
// point of the coercion path is to survive this.
func faNode(runID, path string, writes, bytes, renames, unlinks float64) *graphdb.NodeResponse {
	key := model.FileActivityKey(runID, path)
	return &graphdb.NodeResponse{
		Labels: []string{model.LabelFileActivity},
		Properties: map[string]any{
			model.PropKey: key, "path": path,
			"write_count": writes, "bytes": bytes,
			"rename_count": renames, "unlink_count": unlinks,
		},
	}
}

func runNode(runID, coverage string, lossy bool) *graphdb.NodeResponse {
	// An eBPF ("full") run has write capture; a "partial" seed here models the
	// no-write-capture case (the macOS write-capture case is built explicitly).
	return &graphdb.NodeResponse{
		Labels: []string{model.LabelRun},
		Properties: map[string]any{
			"id": runID, "target": "/bin/x", "coverage": coverage, "lossy": lossy,
			"write_capture": coverage == "full",
		},
	}
}

func seed(runID, coverage string, lossy bool, fa ...*graphdb.NodeResponse) *fakeGraph {
	return &fakeGraph{byLabel: map[string][]*graphdb.NodeResponse{
		model.LabelRun:          {runNode(runID, coverage, lossy)},
		model.LabelFileActivity: fa,
	}}
}

func TestCollect_CoercesFloat64Props(t *testing.T) {
	g := seed("r1", "full", false, faNode("r1", "/a", 5, 4096, 1, 2))
	s, err := Collect(context.Background(), g, "r1", 500)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if s.Coverage != "full (eBPF)" || s.Target != "/bin/x" {
		t.Errorf("run meta = %+v", s)
	}
	if len(s.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(s.Files))
	}
	f := s.Files[0]
	if f.Path != "/a" || f.WriteCount != 5 || f.Bytes != 4096 || f.RenameCount != 1 || f.UnlinkCount != 2 {
		t.Errorf("float64 coercion lost data: %+v", f)
	}
}

func TestCollect_FiltersByRunPrefix(t *testing.T) {
	// A FileActivity node from a DIFFERENT run must not leak into this run.
	g := seed("r1", "full", false, faNode("r1", "/a", 1, 1, 0, 0))
	g.byLabel[model.LabelFileActivity] = append(g.byLabel[model.LabelFileActivity], faNode("OTHER", "/b", 9, 9, 9, 9))
	s, _ := Collect(context.Background(), g, "r1", 500)
	if len(s.Files) != 1 || s.Files[0].Path != "/a" {
		t.Errorf("prefix filter failed: %+v", s.Files)
	}
}

func TestAnalyze_MassWriteAndChurnTripsHigh(t *testing.T) {
	var fa []*graphdb.NodeResponse
	for i := 0; i < TFiles+5; i++ {
		fa = append(fa, faNode("r1", "/data/f"+string(rune('a'+i%26))+string(rune('0'+i/26)), 3, float64(TBytes/10), 1, 1))
	}
	s, _ := Collect(context.Background(), seed("r1", "full", false, fa...), "r1", 500)
	r := Analyze(s)
	if !r.HasHighOrAbove() {
		t.Errorf("mass write + churn should trip >=High, got:\n%s", r.RenderText())
	}
}

func TestAnalyze_BenignFullRunIsCleanButDisclosed(t *testing.T) {
	s, _ := Collect(context.Background(), seed("r1", "full", false, faNode("r1", "/tmp/one", 1, 10, 0, 0)), "r1", 500)
	r := Analyze(s)
	if r.HasHighOrAbove() {
		t.Errorf("a single small write must not trip High:\n%s", r.RenderText())
	}
	// Honesty: the structural-heuristic disclaimer is ALWAYS present.
	if !strings.Contains(r.RenderText(), "structural") {
		t.Errorf("missing structural-heuristic disclaimer:\n%s", r.RenderText())
	}
}

func TestAnalyze_PartialCoverageIsInconclusive(t *testing.T) {
	// A seccomp/replay run has neither write capture nor FileActivity — detection
	// can't run. (runNode gives a "partial" run write_capture=false.)
	s, _ := Collect(context.Background(), seed("r1", "partial", false), "r1", 500)
	r := Analyze(s)
	out := r.RenderText()
	if !strings.Contains(out, "eBPF") || !strings.Contains(out, "inconclusive") {
		t.Errorf("no-write-capture run must say detection is inconclusive:\n%s", out)
	}
}

func TestAnalyze_MacOSWriteCaptureNoBytesReachesHigh(t *testing.T) {
	// macOS: PARTIAL coverage (no full syscall set) BUT write capture, with
	// Bytes=0 (ES exposes no write size). Many files + churn must still reach High
	// via the 2-axis (bytes-adaptive) grading — detection gates on write-capture,
	// not on full coverage.
	mac := &graphdb.NodeResponse{Labels: []string{model.LabelRun}, Properties: map[string]any{
		"id": "mac", "target": "/bin/x", "coverage": "partial", "write_capture": true, "lossy": false,
	}}
	g := &fakeGraph{byLabel: map[string][]*graphdb.NodeResponse{model.LabelRun: {mac}}}
	var fa []*graphdb.NodeResponse
	for i := 0; i < TFiles+5; i++ {
		// bytes = 0 (macOS); each file written once and renamed once (churn).
		fa = append(fa, faNode("mac", "/f"+string(rune('a'+i%26))+string(rune('0'+i/26)), 2, 0, 1, 0))
	}
	g.byLabel[model.LabelFileActivity] = fa

	s, _ := Collect(context.Background(), g, "mac", 500)
	if !s.WriteCapture {
		t.Fatal("write_capture not read from the Run node")
	}
	r := Analyze(s)
	if !r.HasHighOrAbove() {
		t.Errorf("macOS partial+write-capture mass write+churn (bytes=0) should reach >=High:\n%s", r.RenderText())
	}
}
