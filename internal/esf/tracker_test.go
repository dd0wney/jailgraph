package esf

import (
	"bufio"
	"os"
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// TestTracker_FixtureScenario drives the committed eslogger fixture through the
// decoder + tracker (seeded with the scenario's target PID 500) and asserts the
// emitted stream + the file-activity fold, including that an untracked PID's
// write is dropped (the system-wide → subtree filter).
func TestTracker_FixtureScenario(t *testing.T) {
	f, err := os.Open("testdata/eslogger_sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	tr := newTracker(500)
	var stream []collector.BehaviorEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ev, ok, err := decodeLine(line)
		if err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		if !ok {
			continue
		}
		stream = append(stream, tr.OnEvent(ev)...)
	}

	// Streamed (non-file-activity) events.
	has := func(kind collector.EventKind, pid int32, s string) bool {
		for _, e := range stream {
			if e.Kind == kind && e.PID == pid && (s == "" || e.Path == s || e.Exe == s) {
				return true
			}
		}
		return false
	}
	if !has(collector.EventExec, 500, "/usr/bin/myapp") {
		t.Errorf("missing exec of /usr/bin/myapp by 500; stream=%+v", stream)
	}
	if !has(collector.EventSpawn, 501, "") {
		t.Errorf("missing spawn of child 501")
	}
	if !has(collector.EventOpen, 501, "/tmp/data/a.txt") {
		t.Errorf("missing open of a.txt by tracked child 501")
	}

	if !tr.targetExited() {
		t.Error("target (500) exit should set targetExited")
	}

	// File-activity fold.
	fold := map[string]collector.BehaviorEvent{}
	for _, e := range tr.Fold() {
		if e.Kind != collector.EventFileActivity {
			t.Fatalf("Fold emitted non-FileActivity: %v", e)
		}
		if e.Bytes != 0 {
			t.Errorf("macOS has no byte count; %s Bytes=%d want 0", e.Path, e.Bytes)
		}
		fold[e.Path] = e
	}
	// a.txt: 2 writes + 1 rename; b.txt: 1 write; old.txt: 1 unlink.
	if a := fold["/tmp/data/a.txt"]; a.WriteCount != 2 || a.RenameCount != 1 {
		t.Errorf("a.txt fold = %+v, want writes 2 / renames 1", a)
	}
	if b := fold["/tmp/data/b.txt"]; b.WriteCount != 1 {
		t.Errorf("b.txt fold = %+v, want writes 1", b)
	}
	if o := fold["/tmp/data/old.txt"]; o.UnlinkCount != 1 {
		t.Errorf("old.txt fold = %+v, want unlinks 1", o)
	}
	// The untracked PID 999's write to /other/x.txt must NOT appear.
	if _, leaked := fold["/other/x.txt"]; leaked {
		t.Error("untracked PID 999's write leaked into the fold — subtree filter failed")
	}
}
