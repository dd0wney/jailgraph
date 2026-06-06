// This file is platform-neutral (no build tag) so the file-activity fold logic
// is unit-testable without a kernel. The kernel-touching collector that drives
// it lives in collector_linux.go.

package ebpf

import "github.com/dd0wney/jailgraph/internal/collector"

// writeStat mirrors `struct write_stat` in trace.bpf.c (two u64, 16 bytes); it is
// the value type read out of the in-kernel write_stats map.
type writeStat struct {
	Count uint64
	Bytes uint64
}

// fileStat accumulates one file's per-run write/rename/unlink activity. Writes
// come from the in-kernel write_stats map at teardown; renames/unlinks stream
// over the ringbuf and are folded here by name.
type fileStat struct {
	writes  int64
	bytes   int64
	renames int64
	unlinks int64
}

// pathWrite pairs a resolved file path with its in-kernel write aggregate.
type pathWrite struct {
	path string
	stat writeStat
}

// foldFileActivity merges resolved per-path write stats into the rename/unlink
// aggregate (built from streamed events) and returns one EventFileActivity
// BehaviorEvent per file. Pure (no kernel) so it is unit-testable.
func foldFileActivity(agg map[string]*fileStat, writes []pathWrite) []collector.BehaviorEvent {
	for _, w := range writes {
		st := agg[w.path]
		if st == nil {
			st = &fileStat{}
			agg[w.path] = st
		}
		st.writes += int64(w.stat.Count)
		st.bytes += int64(w.stat.Bytes)
	}
	out := make([]collector.BehaviorEvent, 0, len(agg))
	for path, st := range agg {
		out = append(out, collector.BehaviorEvent{
			Kind:        collector.EventFileActivity,
			Path:        path,
			WriteCount:  st.writes,
			Bytes:       st.bytes,
			RenameCount: st.renames,
			UnlinkCount: st.unlinks,
		})
	}
	return out
}
