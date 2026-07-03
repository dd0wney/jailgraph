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

func TestKeyBuilders(t *testing.T) {
	cases := map[string]string{
		RunKey("r1"):            "run:r1",
		SyscallKey(59):          "sys:59",
		SyscallKey(0):           "sys:0",
		FileKey("/etc/passwd"):  "file:/etc/passwd",
		FileKey(""):             "file:",
		CapKey("CAP_SYS_ADMIN"): "cap:CAP_SYS_ADMIN",
		NSKey("net", 5):         "ns:net:5",
		NSKey("user", 0):        "ns:user:0",
		BinaryKey("", ""):       "bin:path:",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
}

func TestEventToGraph_CapProducesHeldCapEdge(t *testing.T) {
	e := collector.BehaviorEvent{Kind: collector.EventCap, PID: 5, CapName: "CAP_NET_RAW", SyscallNr: 185, SyscallName: "capset"}
	nodes, edges := EventToGraph("r1", e)
	var capNode bool
	for _, n := range nodes {
		if n.Labels[0] == LabelCapability {
			capNode = true
			if n.Properties["name"] != "CAP_NET_RAW" {
				t.Errorf("capability name = %v", n.Properties["name"])
			}
		}
	}
	var held bool
	for _, ed := range edges {
		if ed.Type == EdgeHeldCap && ed.ToKey == CapKey("CAP_NET_RAW") {
			held = true
		}
	}
	if !capNode || !held {
		t.Errorf("expected Capability node + HELD_CAP edge (cap=%v held=%v)", capNode, held)
	}
}

func TestEventToGraph_JoinNSProducesJoinedNSEdge(t *testing.T) {
	e := collector.BehaviorEvent{Kind: collector.EventJoinNS, PID: 5, NSType: "net", NSID: 0, SyscallNr: 268, SyscallName: "setns"}
	nodes, edges := EventToGraph("r1", e)
	var nsNode, joined bool
	for _, n := range nodes {
		if n.Labels[0] == LabelNamespace && n.Properties["type"] == "net" {
			nsNode = true
		}
	}
	for _, ed := range edges {
		if ed.Type == EdgeJoinedNS && ed.ToKey == NSKey("net", 0) {
			joined = true
		}
	}
	if !nsNode || !joined {
		t.Errorf("expected Namespace node + JOINED_NS edge (ns=%v joined=%v)", nsNode, joined)
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

func TestEventToGraph_Connect(t *testing.T) {
	e := collector.BehaviorEvent{
		Kind: collector.EventConnect, PID: 100, PPID: 1, Exe: "/usr/bin/curl",
		DstIP: "93.184.216.34", DstPort: 443, Proto: "tcp", ConnCount: 3,
	}
	nodes, edges := EventToGraph("run1", e)

	epKey := EndpointKey("93.184.216.34", 443)
	var ep *Node
	for i := range nodes {
		if nodes[i].Key == epKey {
			ep = &nodes[i]
		}
	}
	if ep == nil {
		t.Fatalf("no Endpoint node with key %q; nodes=%v", epKey, nodes)
	}
	if ep.Labels[0] != LabelEndpoint {
		t.Errorf("label = %v, want %s", ep.Labels, LabelEndpoint)
	}
	if ep.Properties["ip"] != "93.184.216.34" || ep.Properties["port"] != uint16(443) || ep.Properties["proto"] != "tcp" {
		t.Errorf("endpoint props = %v", ep.Properties)
	}

	found := false
	for _, ed := range edges {
		if ed.Type == EdgeConnected && ed.FromKey == ProcessKey("run1", 100) && ed.ToKey == epKey {
			found = true
			if ed.Properties["count"] != int64(3) {
				t.Errorf("CONNECTED count = %v, want 3", ed.Properties["count"])
			}
		}
	}
	if !found {
		t.Errorf("no CONNECTED edge proc->endpoint; edges=%v", edges)
	}
}

func TestEventToGraph_FileActivityIsPerRunNodeWithNoProcessLeak(t *testing.T) {
	e := collector.BehaviorEvent{
		Kind: collector.EventFileActivity, Path: "/data/doc.txt",
		WriteCount: 12, Bytes: 4096, RenameCount: 1, UnlinkCount: 2, Entropy: 7.9,
	}
	nodes, edges := EventToGraph("runX", e)

	// Exactly one node: the FileActivity node. No Process/Syscall preamble leaks
	// (a file-activity summary has no single acting process).
	if len(nodes) != 1 {
		t.Fatalf("want exactly 1 node, got %d: %+v", len(nodes), nodes)
	}
	n := nodes[0]
	if len(n.Labels) != 1 || n.Labels[0] != LabelFileActivity {
		t.Errorf("labels = %v, want [%s]", n.Labels, LabelFileActivity)
	}
	wantKey := FileActivityKey("runX", "/data/doc.txt")
	if n.Key != wantKey || n.Properties[PropKey] != wantKey {
		t.Errorf("key = %q (prop %v), want %q", n.Key, n.Properties[PropKey], wantKey)
	}
	for k, want := range map[string]any{
		"path": "/data/doc.txt", "write_count": int64(12), "bytes": int64(4096),
		"rename_count": int64(1), "unlink_count": int64(2), "entropy": 7.9,
	} {
		if n.Properties[k] != want {
			t.Errorf("prop %s = %v (%T), want %v", k, n.Properties[k], n.Properties[k], want)
		}
	}

	// Exactly one edge: PART_OF from the FileActivity node to the Run.
	if len(edges) != 1 {
		t.Fatalf("want exactly 1 edge, got %d: %+v", len(edges), edges)
	}
	if edges[0].Type != EdgePartOf || edges[0].FromKey != wantKey || edges[0].ToKey != RunKey("runX") {
		t.Errorf("edge = %+v, want PART_OF %s -> %s", edges[0], wantKey, RunKey("runX"))
	}
}
