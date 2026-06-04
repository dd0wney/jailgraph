package collector

import (
	"context"
	"sync"
)

// FakeCollector replays a fixed slice of events. It is the seam that lets the
// buffer, aggregator, ingest worker, and CLI be exercised on any platform —
// including macOS, where the seccomp backend cannot run. Linux CI can record
// real event streams and commit them as fixtures that drive this replayer, so
// cross-platform tests run against realistic data.
type FakeCollector struct {
	events []BehaviorEvent
	errs   []error

	mu     sync.Mutex
	out    chan BehaviorEvent
	errOut chan error
	done   chan struct{}
	closed bool
}

// NewFake returns a FakeCollector that will emit events (in order) and report
// errs on Errors() once draining completes.
func NewFake(events []BehaviorEvent, errs ...error) *FakeCollector {
	return &FakeCollector{events: events, errs: errs}
}

// Start emits the configured events on a buffered channel, then closes both the
// event and error channels. It respects ctx cancellation between events.
func (f *FakeCollector) Start(ctx context.Context) (<-chan BehaviorEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.out != nil {
		return nil, errAlreadyStarted
	}
	// Buffer to the full size so a slow consumer cannot deadlock the replayer;
	// this mirrors the real backend's non-blocking emit into the ring buffer.
	f.out = make(chan BehaviorEvent, len(f.events))
	f.errOut = make(chan error, len(f.errs)+1)
	f.done = make(chan struct{})

	go func() {
		defer close(f.out)
		defer close(f.errOut)
		defer close(f.done)
		for _, e := range f.events {
			select {
			case <-ctx.Done():
				f.errOut <- ctx.Err()
				return
			case f.out <- e:
			}
		}
		for _, err := range f.errs {
			f.errOut <- err
		}
	}()
	return f.out, nil
}

// Errors returns the non-fatal error channel.
func (f *FakeCollector) Errors() <-chan error { return f.errOut }

// Wait blocks until all events have been emitted.
func (f *FakeCollector) Wait() error {
	f.mu.Lock()
	done := f.done
	f.mu.Unlock()
	if done == nil {
		return errNotStarted
	}
	<-done
	return nil
}

// Close is idempotent and a no-op beyond marking the collector closed; the
// replay goroutine owns channel closing.
func (f *FakeCollector) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

var (
	errAlreadyStarted = collectorError("collector already started")
	errNotStarted     = collectorError("collector not started")
)

type collectorError string

func (e collectorError) Error() string { return string(e) }
