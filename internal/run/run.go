// Package run models one learning session. A Run node groups every process,
// syscall, and file observed during a single `jailgraph learn` invocation, and
// records whether the trace was complete (Lossy) so a profile generated from it
// is never silently treated as authoritative when events were dropped.
package run

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Session is the in-memory state of one learning run. It is dependency-free
// (no graphdb import); the ingest worker translates it into a Run node.
type Session struct {
	ID        string
	Target    string
	StartedAt time.Time
	EndedAt   time.Time
	Lossy     bool
	// Coverage records whether the collector observed the FULL syscall set
	// ("full", eBPF) or only a curated subset ("partial", seccomp). It governs
	// whether a least-privilege (default-deny) profile can be generated from
	// this run. Empty is treated as "partial" (the safe default).
	Coverage string
	// Dropped maps a human-readable event-kind name to the number of events of
	// that kind the buffer dropped.
	Dropped map[string]int64
}

// Coverage values recorded on a Run.
const (
	CoverageFull    = "full"
	CoveragePartial = "partial"
)

// New starts a session for target at the given time, assigning a random id.
func New(target string, startedAt time.Time) *Session {
	return &Session{
		ID:        newID(),
		Target:    target,
		StartedAt: startedAt,
		Dropped:   make(map[string]int64),
	}
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is effectively impossible; fall back to a fixed
		// marker rather than panicking in a library.
		return "run-fallback"
	}
	return hex.EncodeToString(b[:])
}
