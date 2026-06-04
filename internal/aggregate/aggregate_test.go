package aggregate

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/model"
)

func findEdge(edges []model.Edge, typ, from, to string) (model.Edge, bool) {
	for _, e := range edges {
		if e.Type == typ && e.FromKey == from && e.ToKey == to {
			return e, true
		}
	}
	return model.Edge{}, false
}

func TestBuilder_DedupsNodesByKey(t *testing.T) {
	b := New("r1")
	// Same process, two events → one Process node, one Syscall node per distinct nr.
	b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 1, SyscallName: "write"})
	b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 1, SyscallName: "write"})
	b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 2, SyscallName: "open"})

	procs, syss := 0, 0
	for _, n := range b.Nodes() {
		switch n.Labels[0] {
		case model.LabelProcess:
			procs++
		case model.LabelSyscall:
			syss++
		}
	}
	if procs != 1 {
		t.Errorf("got %d Process nodes, want 1", procs)
	}
	if syss != 2 {
		t.Errorf("got %d Syscall nodes, want 2", syss)
	}
}

func TestBuilder_SumsInvokedCounts(t *testing.T) {
	b := New("r1")
	for i := 0; i < 3; i++ {
		b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 1, SyscallName: "write"})
	}
	edge, ok := findEdge(b.Edges(), model.EdgeInvoked, model.ProcessKey("r1", 10), model.SyscallKey(1))
	if !ok {
		t.Fatal("missing INVOKED edge")
	}
	if got := edge.Properties["count"]; got != 3 {
		t.Errorf("INVOKED count = %v, want 3", got)
	}
}

func TestBuilder_MergesProcessPropertiesFillingEmpties(t *testing.T) {
	b := New("r1")
	// First sighting: a bare syscall with no exe known.
	b.Add(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 10, SyscallNr: 59, SyscallName: "execve"})
	// Later: the exec reveals the exe path.
	b.Add(collector.BehaviorEvent{Kind: collector.EventExec, PID: 10, Exe: "/bin/sh", BinSHA256: "abc"})

	for _, n := range b.Nodes() {
		if n.Key == model.ProcessKey("r1", 10) {
			if n.Properties["exe"] != "/bin/sh" {
				t.Errorf("process exe = %v, want /bin/sh (later non-empty value should win)", n.Properties["exe"])
			}
		}
	}
}

func TestBuilder_DedupsStructuralEdges(t *testing.T) {
	b := New("r1")
	// Two opens of the same file by the same process → one OPENED edge.
	b.Add(collector.BehaviorEvent{Kind: collector.EventOpen, PID: 10, Path: "/etc/passwd", OpenMode: "r", SyscallNr: 257, SyscallName: "openat"})
	b.Add(collector.BehaviorEvent{Kind: collector.EventOpen, PID: 10, Path: "/etc/passwd", OpenMode: "r", SyscallNr: 257, SyscallName: "openat"})

	opened := 0
	for _, e := range b.Edges() {
		if e.Type == model.EdgeOpened {
			opened++
		}
	}
	if opened != 1 {
		t.Errorf("got %d OPENED edges, want 1 (deduped)", opened)
	}
}

func TestBuilder_DeterministicOrder(t *testing.T) {
	build := func() ([]model.Node, []model.Edge) {
		b := New("r1")
		b.Add(collector.BehaviorEvent{Kind: collector.EventOpen, PID: 10, PPID: 1, Path: "/b", SyscallNr: 257, SyscallName: "openat"})
		b.Add(collector.BehaviorEvent{Kind: collector.EventExec, PID: 10, Exe: "/a", SyscallNr: 59, SyscallName: "execve"})
		return b.Nodes(), b.Edges()
	}
	n1, e1 := build()
	n2, e2 := build()
	if len(n1) != len(n2) || len(e1) != len(e2) {
		t.Fatal("length mismatch across builds")
	}
	for i := range n1 {
		if n1[i].Key != n2[i].Key {
			t.Errorf("node order differs at %d: %q vs %q", i, n1[i].Key, n2[i].Key)
		}
	}
	for i := range e1 {
		if e1[i].Type != e2[i].Type || e1[i].FromKey != e2[i].FromKey || e1[i].ToKey != e2[i].ToKey {
			t.Errorf("edge order differs at %d", i)
		}
	}
}
