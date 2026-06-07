// This file is platform-neutral (no build tag) so the file-activity fold logic
// is unit-testable without a kernel. The kernel-touching collector that drives
// it lives in collector_linux.go.

package ebpf

import (
	"math"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// shannonEntropy returns the Shannon entropy of data in bits/byte (0..8). It is
// the ransomware "encryption" signal: plaintext/source is ~4-5, while encrypted
// or compressed content is ~7.9-8.0. Pure, so it is unit-tested without a kernel.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

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
	entropy float64 // Shannon entropy of the sampled write content (0 if unsampled)
}

// pathWrite pairs a resolved file path with its in-kernel write aggregate and a
// small sample of the written bytes (for entropy). sample is nil when the kernel
// captured no content (e.g. a rename/unlink-only file).
type pathWrite struct {
	path   string
	stat   writeStat
	sample []byte
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
		if len(w.sample) > 0 {
			st.entropy = shannonEntropy(w.sample)
		}
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
			Entropy:     st.entropy,
		})
	}
	return out
}
