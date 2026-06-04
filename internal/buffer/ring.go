// Package buffer decouples the latency-critical capture path from ingestion.
//
// The seccomp supervisor must never block: while it holds a notification, the
// traced thread is suspended. So Push is non-blocking — if the buffer is full it
// drops the *newest* event and records the drop rather than waiting. Dropping
// the newest (not the oldest) preserves the structural events that burst at
// process startup, sacrificing only replaceable steady-state syscall counts.
//
// Drops are never silent: they are counted per kind and surfaced so the run can
// be marked lossy. The Ring is the concrete Sink for increment 1; a durable
// WAL-backed Sink can replace it later without touching capture or ingest.
package buffer

import (
	"sync"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// Ring is a bounded, concurrency-safe FIFO of BehaviorEvents with a
// drop-newest overflow policy.
type Ring struct {
	ch chan collector.BehaviorEvent

	mu      sync.Mutex
	drops   map[collector.EventKind]int64
	dropped int64
}

// New returns a Ring holding up to capacity events.
func New(capacity int) *Ring {
	return &Ring{
		ch:    make(chan collector.BehaviorEvent, capacity),
		drops: make(map[collector.EventKind]int64),
	}
}

// Push enqueues e without blocking. It returns false if the buffer was full and
// e was dropped (the drop is recorded by kind).
func (r *Ring) Push(e collector.BehaviorEvent) bool {
	select {
	case r.ch <- e:
		return true
	default:
		r.mu.Lock()
		r.drops[e.Kind]++
		r.dropped++
		r.mu.Unlock()
		return false
	}
}

// Drain removes and returns up to max buffered events in FIFO order. It returns
// immediately with whatever is available (possibly empty).
func (r *Ring) Drain(max int) []collector.BehaviorEvent {
	out := make([]collector.BehaviorEvent, 0, max)
	for len(out) < max {
		select {
		case e := <-r.ch:
			out = append(out, e)
		default:
			return out
		}
	}
	return out
}

// Len reports the number of buffered events not yet drained.
func (r *Ring) Len() int { return len(r.ch) }

// Drops returns a copy of the per-kind drop counts.
func (r *Ring) Drops() map[collector.EventKind]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[collector.EventKind]int64, len(r.drops))
	for k, v := range r.drops {
		out[k] = v
	}
	return out
}

// TotalDropped reports the total number of dropped events across all kinds.
func (r *Ring) TotalDropped() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
