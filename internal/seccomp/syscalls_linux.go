//go:build linux

package seccomp

import "github.com/dd0wney/jailgraph/internal/collector"

// syscallSpec maps a syscall number to its name and the event kind it produces.
type syscallSpec struct {
	nr   int
	name string
	kind collector.EventKind
}

// tables holds the lookup maps derived once from the per-arch flagged set.
type tables struct {
	nrs   []int
	names map[int]string
	kinds map[int]collector.EventKind
}

func buildTables() tables {
	specs := archFlagged()
	t := tables{
		names: make(map[int]string, len(specs)),
		kinds: make(map[int]collector.EventKind, len(specs)),
	}
	for _, s := range specs {
		t.nrs = append(t.nrs, s.nr)
		t.names[s.nr] = s.name
		t.kinds[s.nr] = s.kind
	}
	return t
}
