package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dd0wney/jailgraph/internal/detect"
	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// fakeGraph implements graphClient: it records writes and serves reads from
// seeded maps, so the subcommand bodies run without a real graphdb server.
type fakeGraph struct {
	byLabel  map[string][]*graphdb.NodeResponse // NodesByLabel
	byNode   map[uint64][]*graphdb.NodeResponse // Traverse neighbors
	nextID   uint64
	gotNodes []graphdb.NodeRequest
	gotEdges []graphdb.EdgeRequest
}

func newFakeGraph() *fakeGraph {
	return &fakeGraph{byLabel: map[string][]*graphdb.NodeResponse{}, byNode: map[uint64][]*graphdb.NodeResponse{}}
}

func (f *fakeGraph) CreateNode(_ context.Context, req graphdb.NodeRequest) (*graphdb.NodeResponse, error) {
	f.nextID++
	f.gotNodes = append(f.gotNodes, req)
	return &graphdb.NodeResponse{ID: f.nextID, Labels: req.Labels, Properties: req.Properties}, nil
}

func (f *fakeGraph) BatchNodes(_ context.Context, reqs []graphdb.NodeRequest) ([]*graphdb.NodeResponse, error) {
	out := make([]*graphdb.NodeResponse, 0, len(reqs))
	for _, r := range reqs {
		f.nextID++
		f.gotNodes = append(f.gotNodes, r)
		out = append(out, &graphdb.NodeResponse{ID: f.nextID, Labels: r.Labels, Properties: r.Properties})
	}
	return out, nil
}

func (f *fakeGraph) BatchEdges(_ context.Context, reqs []graphdb.EdgeRequest) ([]*graphdb.EdgeResponse, error) {
	out := make([]*graphdb.EdgeResponse, 0, len(reqs))
	for _, r := range reqs {
		f.nextID++
		f.gotEdges = append(f.gotEdges, r)
		out = append(out, &graphdb.EdgeResponse{ID: f.nextID, FromNodeID: r.FromNodeID, ToNodeID: r.ToNodeID, Type: r.Type})
	}
	return out, nil
}

func (f *fakeGraph) NodesByLabel(_ context.Context, label string, _ int) ([]*graphdb.NodeResponse, error) {
	return f.byLabel[label], nil
}

func (f *fakeGraph) Traverse(_ context.Context, startID uint64, _ int) ([]*graphdb.NodeResponse, error) {
	return f.byNode[startID], nil
}

// withFakeGraph swaps the newGraphClient seam for the test's duration.
func withFakeGraph(t *testing.T, f *fakeGraph) {
	t.Helper()
	orig := newGraphClient
	newGraphClient = func(string, string) graphClient { return f }
	t.Cleanup(func() { newGraphClient = orig })
}

func node(id uint64, label string, props map[string]any) *graphdb.NodeResponse {
	if props == nil {
		props = map[string]any{}
	}
	return &graphdb.NodeResponse{ID: id, Labels: []string{label}, Properties: props}
}

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name       string
		argv       []string
		wantFlags  []string
		wantTarget string
		wantArgs   []string
	}{
		{"flags then target", []string{"-v", "--", "cat", "/etc/hostname"}, []string{"-v"}, "cat", []string{"/etc/hostname"}},
		{"no separator", []string{"-v", "x"}, []string{"-v", "x"}, "", nil},
		{"separator at end", []string{"-v", "--"}, []string{"-v"}, "", nil},
		{"separator first", []string{"--", "cat"}, []string{}, "cat", nil},
		{"empty", nil, nil, "", nil},
		{"multiple separators", []string{"--", "a", "--", "b"}, []string{}, "a", []string{"--", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags, target, args := splitArgs(c.argv)
			if target != c.wantTarget {
				t.Errorf("target = %q, want %q", target, c.wantTarget)
			}
			if !eq(flags, c.wantFlags) {
				t.Errorf("flags = %v, want %v", flags, c.wantFlags)
			}
			if !eq(args, c.wantArgs) {
				t.Errorf("args = %v, want %v", args, c.wantArgs)
			}
		})
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("JG_TEST_ENV", "value")
	if got := envOr("JG_TEST_ENV", "def"); got != "value" {
		t.Errorf("present: got %q, want value", got)
	}
	if got := envOr("JG_TEST_UNSET_XYZ", "def"); got != "def" {
		t.Errorf("absent: got %q, want def", got)
	}
	t.Setenv("JG_TEST_ENV", "")
	if got := envOr("JG_TEST_ENV", "def"); got != "def" {
		t.Errorf("empty value should fall back to default, got %q", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"a,b,c":   {"a", "b", "c"},
		" a , b ": {"a", "b"},
		"a,,b,":   {"a", "b"}, // empty/trailing parts dropped
		"":        nil,
		"   ":     nil,
		"only":    {"only"},
	}
	for in, want := range cases {
		if got := splitCSV(in); !eq(got, want) {
			t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolveExit(t *testing.T) {
	if code, msg := resolveExit(errors.New("boom")); code != 1 || msg != "boom" {
		t.Errorf("plain error => (%d,%q), want (1,boom)", code, msg)
	}
	if code, msg := resolveExit(&exitErr{code: 2, msg: "lossy"}); code != 2 || msg != "lossy" {
		t.Errorf("exitErr{2,lossy} => (%d,%q), want (2,lossy)", code, msg)
	}
	// Drift case: code 1, empty message (report already printed → no stderr line).
	if code, msg := resolveExit(&exitErr{code: 1, msg: ""}); code != 1 || msg != "" {
		t.Errorf("exitErr{1,\"\"} => (%d,%q), want (1,\"\")", code, msg)
	}
}

func TestLoadFixture(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Valid: a one-event array.
	valid := write("ok.json", `[{"Kind":1,"PID":10,"Exe":"/bin/sh"}]`)
	evs, err := loadFixture(valid)
	if err != nil || len(evs) != 1 || evs[0].Exe != "/bin/sh" {
		t.Errorf("valid fixture: events=%v err=%v", evs, err)
	}
	// Empty array is valid → zero events.
	if evs, err := loadFixture(write("empty.json", `[]`)); err != nil || len(evs) != 0 {
		t.Errorf("empty array: events=%v err=%v", evs, err)
	}
	// Invalid JSON → error.
	if _, err := loadFixture(write("bad.json", `{not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
	// Missing file → error.
	if _, err := loadFixture(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("missing file should error")
	}
}

func TestRunLearn_ReplayEndToEnd(t *testing.T) {
	f := newFakeGraph()
	withFakeGraph(t, f)
	dir := t.TempDir()
	fixture := filepath.Join(dir, "events.json")
	// sh execs, opens a file: produces Run + Process + Binary + File + Syscall nodes.
	if err := os.WriteFile(fixture, []byte(`[
		{"Kind":1,"PID":10,"PPID":1,"Exe":"/bin/sh","SyscallNr":59,"SyscallName":"execve"},
		{"Kind":3,"PID":10,"Path":"/etc/hostname","OpenMode":"r","SyscallNr":257,"SyscallName":"openat"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runLearn([]string{"--replay", fixture, "--api-key", "x"}); err != nil {
		t.Fatalf("runLearn: %v", err)
	}
	// A Run node was created first, marked partial coverage (replay isn't eBPF).
	var sawRun bool
	labels := map[string]int{}
	for _, n := range f.gotNodes {
		if len(n.Labels) == 0 {
			continue
		}
		labels[n.Labels[0]]++
		if n.Labels[0] == model.LabelRun {
			sawRun = true
			if n.Properties["coverage"] != "partial" {
				t.Errorf("replay run coverage = %v, want partial", n.Properties["coverage"])
			}
		}
	}
	if !sawRun {
		t.Error("expected a Run node to be created")
	}
	for _, want := range []string{model.LabelProcess, model.LabelBinary, model.LabelFile, model.LabelSyscall} {
		if labels[want] == 0 {
			t.Errorf("expected a %s node written; saw %v", want, labels)
		}
	}
	if len(f.gotEdges) == 0 {
		t.Error("expected edges written")
	}
}

func TestRunProfile_FirejailToFile(t *testing.T) {
	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{node(1, model.LabelRun, map[string]any{"id": "r1", "coverage": "full"})}
	f.byLabel[model.LabelProcess] = []*graphdb.NodeResponse{node(10, model.LabelProcess, map[string]any{model.PropKey: model.ProcessKey("r1", 10)})}
	f.byNode[10] = []*graphdb.NodeResponse{
		node(20, model.LabelSyscall, map[string]any{"name": "openat"}),
		node(21, model.LabelFile, map[string]any{"path": "/etc/hostname"}),
		node(22, model.LabelBinary, map[string]any{"path": "/bin/sh"}),
	}
	withFakeGraph(t, f)
	out := filepath.Join(t.TempDir(), "prof")
	if err := runProfile([]string{"--run", "r1", "--format", "firejail", "--out", out, "--api-key", "x"}); err != nil {
		t.Fatalf("runProfile: %v", err)
	}
	data, err := os.ReadFile(out + ".profile")
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if !strings.Contains(string(data), "whitelist /etc") {
		t.Errorf("firejail profile missing evidence-based whitelist:\n%s", data)
	}
}

func TestRunProfile_EnforceNeedsFullCoverage(t *testing.T) {
	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{node(1, model.LabelRun, map[string]any{"id": "r1", "coverage": "partial"})}
	withFakeGraph(t, f)
	err := runProfile([]string{"--run", "r1", "--enforce", "--format", "seccomp", "--api-key", "x"})
	if err == nil {
		t.Fatal("expected --enforce on a partial-coverage run to error")
	}
}

func TestRunProfile_MissingRun(t *testing.T) {
	withFakeGraph(t, newFakeGraph())
	if err := runProfile([]string{"--api-key", "x"}); err == nil {
		t.Fatal("expected error when --run is missing")
	}
}

func auditFake() *fakeGraph {
	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{
		node(1, model.LabelRun, map[string]any{"id": "base", "coverage": "full"}),
		node(2, model.LabelRun, map[string]any{"id": "cand", "coverage": "full"}),
	}
	f.byLabel[model.LabelProcess] = []*graphdb.NodeResponse{
		node(10, model.LabelProcess, map[string]any{model.PropKey: model.ProcessKey("base", 10)}),
		node(20, model.LabelProcess, map[string]any{model.PropKey: model.ProcessKey("cand", 20)}),
	}
	return f
}

func TestRunAudit_NoDriftReturnsNil(t *testing.T) {
	f := auditFake()
	// Both runs invoke the same syscall → no stable-dimension drift.
	f.byNode[10] = []*graphdb.NodeResponse{node(30, model.LabelSyscall, map[string]any{"name": "openat"})}
	f.byNode[20] = []*graphdb.NodeResponse{node(31, model.LabelSyscall, map[string]any{"name": "openat"})}
	withFakeGraph(t, f)
	if err := runAudit([]string{"--baseline", "base", "--against", "cand", "--api-key", "x"}); err != nil {
		t.Errorf("no-drift audit should return nil, got %v", err)
	}
}

func TestRunAudit_DriftExitsOne(t *testing.T) {
	f := auditFake()
	// Candidate invokes a NEW dangerous syscall → additive drift (security mode).
	f.byNode[10] = []*graphdb.NodeResponse{node(30, model.LabelSyscall, map[string]any{"name": "openat"})}
	f.byNode[20] = []*graphdb.NodeResponse{
		node(31, model.LabelSyscall, map[string]any{"name": "openat"}),
		node(32, model.LabelSyscall, map[string]any{"name": "setns"}),
	}
	withFakeGraph(t, f)
	err := runAudit([]string{"--baseline", "base", "--against", "cand", "--api-key", "x"})
	code, _ := resolveExit(err)
	if code != 1 {
		t.Errorf("drift should exit 1, got code %d (err %v)", code, err)
	}
}

func TestRunAudit_FlagErrorsExitTwo(t *testing.T) {
	withFakeGraph(t, newFakeGraph())
	for _, argv := range [][]string{
		{},                  // missing both
		{"--baseline", "b"}, // missing --against
		{"--baseline", "b", "--against", "c", "--mode", "x"}, // bad mode
	} {
		err := runAudit(argv)
		if code, _ := resolveExit(err); code != 2 {
			t.Errorf("runAudit(%v) exit = %d, want 2 (err %v)", argv, code, err)
		}
	}
}

// reportFake seeds one run whose single process touched the given neighbors.
func reportFake(coverage string, neighbors ...*graphdb.NodeResponse) *fakeGraph {
	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{
		node(1, model.LabelRun, map[string]any{"id": "r1", "coverage": coverage, "target": "/bin/x"}),
	}
	f.byLabel[model.LabelProcess] = []*graphdb.NodeResponse{
		node(10, model.LabelProcess, map[string]any{model.PropKey: model.ProcessKey("r1", 10)}),
	}
	f.byNode[10] = neighbors
	return f
}

func TestRunReport_HighFindingExitsOne(t *testing.T) {
	// Full-coverage run that opened a sensitive file -> a High finding -> exit 1.
	f := reportFake("full",
		node(30, model.LabelSyscall, map[string]any{"name": "setns"}),
		node(31, model.LabelFile, map[string]any{"path": "/etc/shadow"}),
	)
	withFakeGraph(t, f)
	err := runReport([]string{"--run", "r1", "--api-key", "x"})
	if code, _ := resolveExit(err); code != 1 {
		t.Errorf("a High finding should exit 1, got code %d (err %v)", code, err)
	}
}

func TestRunReport_CleanExitsZero(t *testing.T) {
	// Full-coverage run, only a benign (non-gateable) syscall, no caps/files ->
	// only Info findings -> exit 0 (nil).
	f := reportFake("full", node(30, model.LabelSyscall, map[string]any{"name": "read"}))
	withFakeGraph(t, f)
	if err := runReport([]string{"--run", "r1", "--api-key", "x"}); err != nil {
		t.Errorf("a clean full-coverage report should return nil, got %v", err)
	}
}

func TestRunReport_MissingRunExitsTwo(t *testing.T) {
	withFakeGraph(t, newFakeGraph())
	err := runReport([]string{"--api-key", "x"})
	if code, _ := resolveExit(err); code != 2 {
		t.Errorf("missing --run should exit 2, got code %d (err %v)", code, err)
	}
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func faNodeCLI(runID, path string, writes, bytes, renames, unlinks float64) *graphdb.NodeResponse {
	return node(0, model.LabelFileActivity, map[string]any{
		model.PropKey: model.FileActivityKey(runID, path), "path": path,
		"write_count": writes, "bytes": bytes, "rename_count": renames, "unlink_count": unlinks,
	})
}

func TestRunDetect_RansomwareSignatureExitsOne(t *testing.T) {
	// Lower the thresholds so a small fixture trips the structural signature.
	defer func(f int, c, b int64) { detect.TFiles, detect.TChurn, detect.TBytes = f, c, b }(detect.TFiles, detect.TChurn, detect.TBytes)
	detect.TFiles, detect.TChurn, detect.TBytes = 2, 1, 1

	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{node(1, model.LabelRun, map[string]any{"id": "r1", "coverage": "full"})}
	f.byLabel[model.LabelFileActivity] = []*graphdb.NodeResponse{
		faNodeCLI("r1", "/a", 3, 100, 1, 1),
		faNodeCLI("r1", "/b", 3, 100, 1, 1),
		faNodeCLI("r1", "/c", 3, 100, 1, 1),
	}
	withFakeGraph(t, f)
	err := runDetect([]string{"--run", "r1", "--api-key", "x"})
	if code, _ := resolveExit(err); code != 1 {
		t.Errorf("ransomware signature should exit 1, got code %d (err %v)", code, err)
	}
}

func TestRunDetect_BenignExitsZero(t *testing.T) {
	f := newFakeGraph()
	f.byLabel[model.LabelRun] = []*graphdb.NodeResponse{node(1, model.LabelRun, map[string]any{"id": "r1", "coverage": "full"})}
	f.byLabel[model.LabelFileActivity] = []*graphdb.NodeResponse{faNodeCLI("r1", "/tmp/x", 1, 10, 0, 0)}
	withFakeGraph(t, f)
	if err := runDetect([]string{"--run", "r1", "--api-key", "x"}); err != nil {
		t.Errorf("benign full-coverage run should exit 0 (nil), got %v", err)
	}
}

func TestRunDetect_MissingRunExitsTwo(t *testing.T) {
	withFakeGraph(t, newFakeGraph())
	err := runDetect([]string{"--api-key", "x"})
	if code, _ := resolveExit(err); code != 2 {
		t.Errorf("missing --run should exit 2, got code %d (err %v)", code, err)
	}
}
