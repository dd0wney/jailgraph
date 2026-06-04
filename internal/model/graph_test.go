package model

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestBinaryKey_FallsBackToPathWhenUnhashed(t *testing.T) {
	if got := BinaryKey("abc123", "/bin/sh"); got != "bin:sha:abc123" {
		t.Errorf("hashed key = %q", got)
	}
	if got := BinaryKey("", "/bin/sh"); got != "bin:path:/bin/sh" {
		t.Errorf("fallback key = %q", got)
	}
	// A hashed and an unhashed observation of the same path must not collide.
	if BinaryKey("abc123", "/bin/sh") == BinaryKey("", "/bin/sh") {
		t.Error("hashed and unhashed keys collided")
	}
}

func TestProcessKey_ScopedToRun(t *testing.T) {
	if ProcessKey("runA", 100) == ProcessKey("runB", 100) {
		t.Error("same pid in different runs must produce different keys")
	}
}

func TestKeyKind(t *testing.T) {
	cases := map[string]string{
		"bin:sha:abc":      "bin",
		"sys:59":           "sys",
		"file:/etc/passwd": "file",
		"naked":            "naked",
	}
	for in, want := range cases {
		if got := KeyKind(in); got != want {
			t.Errorf("KeyKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventToGraph_ExecProducesBinaryAndExecEdge(t *testing.T) {
	e := collector.BehaviorEvent{
		Kind: collector.EventExec, PID: 10, PPID: 1,
		Exe: "/bin/sh", BinSHA256: "deadbeef",
		SyscallNr: 59, SyscallName: "execve",
	}
	nodes, edges := EventToGraph("r1", e)

	wantNodeLabels := map[string]bool{LabelProcess: false, LabelSyscall: false, LabelBinary: false}
	for _, n := range nodes {
		wantNodeLabels[n.Labels[0]] = true
		if n.Properties[PropKey] != n.Key {
			t.Errorf("node %q missing self-referential %s property", n.Key, PropKey)
		}
	}
	for lbl, seen := range wantNodeLabels {
		if !seen {
			t.Errorf("missing expected node label %q", lbl)
		}
	}

	wantEdges := map[string]bool{EdgePartOf: false, EdgeSpawned: false, EdgeInvoked: false, EdgeExec: false}
	for _, ed := range edges {
		wantEdges[ed.Type] = true
	}
	for typ, seen := range wantEdges {
		if !seen {
			t.Errorf("missing expected edge type %q", typ)
		}
	}
}

func TestEventToGraph_SpawnedDerivedFromParentNotCloneSyscall(t *testing.T) {
	// A clone event names the *parent* PID; the child pid is unknowable at notify
	// time. The SPAWNED edge must come from the PPID linkage of a later event.
	child := collector.BehaviorEvent{Kind: collector.EventOpen, PID: 20, PPID: 10, Path: "/tmp/x"}
	_, edges := EventToGraph("r1", child)

	var found bool
	for _, ed := range edges {
		if ed.Type == EdgeSpawned {
			found = true
			if ed.FromKey != ProcessKey("r1", 10) || ed.ToKey != ProcessKey("r1", 20) {
				t.Errorf("SPAWNED edge = %s->%s, want parent10->child20", ed.FromKey, ed.ToKey)
			}
		}
	}
	if !found {
		t.Error("expected a SPAWNED edge derived from PPID")
	}
}

func TestEventToGraph_NoSpawnEdgeForRootOrSelfParent(t *testing.T) {
	for _, ppid := range []int32{0, 10} { // 0 = no parent; 10 = self
		e := collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, PPID: ppid, SyscallNr: 1, SyscallName: "write"}
		_, edges := EventToGraph("r1", e)
		for _, ed := range edges {
			if ed.Type == EdgeSpawned {
				t.Errorf("ppid=%d should not yield a SPAWNED edge", ppid)
			}
		}
	}
}

func TestEventToGraph_OpenCarriesMode(t *testing.T) {
	e := collector.BehaviorEvent{Kind: collector.EventOpen, PID: 5, Path: "/etc/shadow", OpenMode: "r", SyscallNr: 257, SyscallName: "openat"}
	_, edges := EventToGraph("r1", e)
	var found bool
	for _, ed := range edges {
		if ed.Type == EdgeOpened {
			found = true
			if ed.Properties["mode"] != "r" {
				t.Errorf("OPENED mode = %v, want r", ed.Properties["mode"])
			}
		}
	}
	if !found {
		t.Error("expected an OPENED edge")
	}
}
