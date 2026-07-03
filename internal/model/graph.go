package model

import "github.com/dd0wney/jailgraph/internal/collector"

// PropKey is the property name under which each node carries its natural key.
// The ingest worker embeds it on write and reads it back from the (out-of-order)
// batch response to reconcile created nodes to keys.
const PropKey = "_key"

// Node is a graphdb node keyed by its natural key. Properties is intentionally
// map[string]any (not graphdb's typed Value) so this package stays free of any
// graphdb dependency; the graphdb client encodes the conversion.
type Node struct {
	Key        string
	Labels     []string
	Properties map[string]any
}

// Edge is a graphdb edge addressed by the natural keys of its endpoints. The
// ingest worker resolves FromKey/ToKey to graphdb ids before writing.
type Edge struct {
	Type       string
	FromKey    string
	ToKey      string
	Properties map[string]any
}

// EventToGraph explodes one BehaviorEvent into the nodes and edges it implies,
// within the given run. It is pure and stateless: deduplication of repeated
// nodes and aggregation of repeated INVOKED edges are the aggregator's job (see
// internal/aggregate), so every EventSyscall here yields an INVOKED edge with
// count 1.
//
// Every event materialises the acting Process and its PART_OF link to the Run,
// plus a SPAWNED edge from its parent when a parent PID is known — that parent
// linkage, not the clone syscall, is how the process tree is reconstructed
// (the child PID is not observable at clone-notify time; see the package doc on
// the collector).
func EventToGraph(runID string, e collector.BehaviorEvent) ([]Node, []Edge) {
	// A file-activity summary is a run-level aggregate with no single acting
	// process, so it bypasses the Process/INVOKED preamble entirely.
	if e.Kind == collector.EventFileActivity {
		return fileActivityGraph(runID, e)
	}

	procKey := ProcessKey(runID, e.PID)
	nodes := []Node{
		{
			Key:    procKey,
			Labels: []string{LabelProcess},
			Properties: map[string]any{
				"pid":   e.PID,
				"ppid":  e.PPID,
				"exe":   e.Exe,
				"uid":   e.UID,
				PropKey: procKey,
			},
		},
	}
	edges := []Edge{
		{Type: EdgePartOf, FromKey: procKey, ToKey: RunKey(runID)},
	}

	// Parent linkage → SPAWNED. Guard against PPID 0 (kernel/no parent) and the
	// degenerate self-parent case.
	if e.PPID != 0 && e.PPID != e.PID {
		edges = append(edges, Edge{
			Type:    EdgeSpawned,
			FromKey: ProcessKey(runID, e.PPID),
			ToKey:   procKey,
		})
	}

	// Every event records the syscall it rode in on, so the INVOKED surface is
	// complete regardless of kind.
	if e.SyscallName != "" {
		sysKey := SyscallKey(e.SyscallNr)
		nodes = append(nodes, Node{
			Key:    sysKey,
			Labels: []string{LabelSyscall},
			Properties: map[string]any{
				"nr":    e.SyscallNr,
				"name":  e.SyscallName,
				PropKey: sysKey,
			},
		})
		edges = append(edges, Edge{
			Type:       EdgeInvoked,
			FromKey:    procKey,
			ToKey:      sysKey,
			Properties: map[string]any{"count": 1},
		})
	}

	switch e.Kind {
	case collector.EventExec:
		binKey := BinaryKey(e.BinSHA256, e.Exe)
		props := map[string]any{"path": e.Exe, PropKey: binKey}
		if e.BinSHA256 != "" {
			props["sha256"] = e.BinSHA256
		}
		nodes = append(nodes, Node{Key: binKey, Labels: []string{LabelBinary}, Properties: props})
		edges = append(edges, Edge{Type: EdgeExec, FromKey: procKey, ToKey: binKey})

	case collector.EventOpen:
		fileKey := FileKey(e.Path)
		nodes = append(nodes, Node{
			Key:        fileKey,
			Labels:     []string{LabelFile},
			Properties: map[string]any{"path": e.Path, PropKey: fileKey},
		})
		edges = append(edges, Edge{
			Type:       EdgeOpened,
			FromKey:    procKey,
			ToKey:      fileKey,
			Properties: map[string]any{"mode": e.OpenMode},
		})

	case collector.EventCap:
		capKey := CapKey(e.CapName)
		nodes = append(nodes, Node{
			Key:        capKey,
			Labels:     []string{LabelCapability},
			Properties: map[string]any{"name": e.CapName, PropKey: capKey},
		})
		edges = append(edges, Edge{Type: EdgeHeldCap, FromKey: procKey, ToKey: capKey})

	case collector.EventJoinNS:
		nsKey := NSKey(e.NSType, e.NSID)
		nodes = append(nodes, Node{
			Key:        nsKey,
			Labels:     []string{LabelNamespace},
			Properties: map[string]any{"type": e.NSType, "id": e.NSID, PropKey: nsKey},
		})
		edges = append(edges, Edge{Type: EdgeJoinedNS, FromKey: procKey, ToKey: nsKey})

	case collector.EventConnect:
		// The connect is pre-folded per (process, destination) by the collector,
		// so exactly one CONNECTED edge exists per pair with the full count — the
		// aggregator's non-INVOKED dedup preserves it as-is (no summation needed),
		// matching how FileActivity is pre-folded.
		epKey := EndpointKey(e.DstIP, e.DstPort)
		nodes = append(nodes, Node{
			Key:    epKey,
			Labels: []string{LabelEndpoint},
			Properties: map[string]any{
				"ip": e.DstIP, "port": e.DstPort, "proto": e.Proto, PropKey: epKey,
			},
		})
		count := e.ConnCount
		if count == 0 {
			count = 1
		}
		edges = append(edges, Edge{
			Type: EdgeConnected, FromKey: procKey, ToKey: epKey,
			Properties: map[string]any{"count": count},
		})

	case collector.EventDNS:
		// Like EventConnect, the collector pre-folds queries per (process, name);
		// exactly one RESOLVED edge exists per pair with the full count.
		dk := DomainKey(e.Domain)
		nodes = append(nodes, Node{
			Key:        dk,
			Labels:     []string{LabelDomain},
			Properties: map[string]any{"name": e.Domain, PropKey: dk},
		})
		count := e.ResolveCount
		if count == 0 {
			count = 1
		}
		edges = append(edges, Edge{
			Type: EdgeResolved, FromKey: procKey, ToKey: dk,
			Properties: map[string]any{"count": count},
		})

	case collector.EventSpawn, collector.EventSyscall:
		// Process node + INVOKED (above) already capture these; the SPAWNED edge
		// is derived from PPID linkage, not the clone notification.
	}

	return nodes, edges
}

// fileActivityGraph maps a per-(run, file) write/rename/unlink summary to a single
// per-run FileActivity node anchored to the Run by PART_OF. The collector folds
// activity across the process tree before emitting, so exactly one event — and
// thus one node — exists per (run, path); the aggregator's node dedupe needs no
// property summation. The property map is flat so entropy (phase 2) is one more
// key with no rework.
func fileActivityGraph(runID string, e collector.BehaviorEvent) ([]Node, []Edge) {
	key := FileActivityKey(runID, e.Path)
	node := Node{
		Key:    key,
		Labels: []string{LabelFileActivity},
		Properties: map[string]any{
			"path":         e.Path,
			"write_count":  e.WriteCount,
			"bytes":        e.Bytes,
			"rename_count": e.RenameCount,
			"unlink_count": e.UnlinkCount,
			"entropy":      e.Entropy,
			PropKey:        key,
		},
	}
	edges := []Edge{{Type: EdgePartOf, FromKey: key, ToKey: RunKey(runID)}}
	return []Node{node}, edges
}
