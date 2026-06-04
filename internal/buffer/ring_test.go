package buffer

import (
	"runtime"
	"sync"
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestRing_PushAndDrainFIFO(t *testing.T) {
	r := New(10)
	for i := int32(0); i < 5; i++ {
		if !r.Push(collector.BehaviorEvent{PID: i}) {
			t.Fatalf("push %d unexpectedly dropped", i)
		}
	}
	got := r.Drain(10)
	if len(got) != 5 {
		t.Fatalf("drained %d, want 5", len(got))
	}
	for i := range got {
		if got[i].PID != int32(i) {
			t.Errorf("order broken: pos %d had pid %d", i, got[i].PID)
		}
	}
}

func TestRing_DropsNewestWhenFull(t *testing.T) {
	r := New(2)
	if !r.Push(collector.BehaviorEvent{Kind: collector.EventExec, PID: 1}) {
		t.Fatal("push 1 dropped")
	}
	if !r.Push(collector.BehaviorEvent{Kind: collector.EventExec, PID: 2}) {
		t.Fatal("push 2 dropped")
	}
	// Buffer full: the newest is rejected, the earlier two survive.
	if r.Push(collector.BehaviorEvent{Kind: collector.EventSyscall, PID: 3}) {
		t.Fatal("push 3 should have been dropped")
	}
	got := r.Drain(10)
	if len(got) != 2 || got[0].PID != 1 || got[1].PID != 2 {
		t.Fatalf("survivors = %+v, want pids [1 2]", got)
	}
}

func TestRing_RecordsDropsByKind(t *testing.T) {
	r := New(1)
	r.Push(collector.BehaviorEvent{Kind: collector.EventExec}) // fills buffer
	r.Push(collector.BehaviorEvent{Kind: collector.EventSyscall})
	r.Push(collector.BehaviorEvent{Kind: collector.EventSyscall})
	r.Push(collector.BehaviorEvent{Kind: collector.EventOpen})

	drops := r.Drops()
	if drops[collector.EventSyscall] != 2 {
		t.Errorf("syscall drops = %d, want 2", drops[collector.EventSyscall])
	}
	if drops[collector.EventOpen] != 1 {
		t.Errorf("open drops = %d, want 1", drops[collector.EventOpen])
	}
	if r.TotalDropped() != 3 {
		t.Errorf("total dropped = %d, want 3", r.TotalDropped())
	}
}

func TestRing_DrainRespectsMax(t *testing.T) {
	r := New(100)
	for i := 0; i < 100; i++ {
		r.Push(collector.BehaviorEvent{})
	}
	if got := r.Drain(30); len(got) != 30 {
		t.Errorf("drain(30) = %d, want 30", len(got))
	}
	if r.Len() != 70 {
		t.Errorf("remaining = %d, want 70", r.Len())
	}
}

func TestRing_Drain0(t *testing.T) {
	r := New(4)
	r.Push(collector.BehaviorEvent{})
	if got := r.Drain(0); len(got) != 0 {
		t.Errorf("Drain(0) = %d items, want 0", len(got))
	}
	if r.Len() != 1 {
		t.Errorf("Drain(0) should not consume; Len = %d, want 1", r.Len())
	}
}

func TestRing_ConcurrentPushAndDrain(t *testing.T) {
	// The real main.go pattern: producers Push while a consumer Drains. Run under
	// -race; assert nothing is lost or duplicated (pushed == drained + dropped + remaining).
	const producers, perProducer = 8, 500
	r := New(256)
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				r.Push(collector.BehaviorEvent{Kind: collector.EventSyscall})
			}
		}()
	}
	prodDone := make(chan struct{})
	go func() { wg.Wait(); close(prodDone) }()

	// Single consumer draining concurrently with the producers.
	var drained int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n := len(r.Drain(64))
			drained += int64(n)
			if n == 0 {
				select {
				case <-prodDone:
					drained += int64(len(r.Drain(1 << 20))) // final sweep
					return
				default:
					runtime.Gosched()
				}
			}
		}
	}()
	<-done

	total := drained + r.TotalDropped() + int64(r.Len())
	if total != producers*perProducer {
		t.Errorf("accounting off: drained=%d dropped=%d remaining=%d total=%d, want %d",
			drained, r.TotalDropped(), r.Len(), total, producers*perProducer)
	}
}

func TestRing_ConcurrentPushIsSafe(t *testing.T) {
	r := New(1000)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Push(collector.BehaviorEvent{Kind: collector.EventSyscall})
			}
		}()
	}
	wg.Wait()
	// 1000 pushed into capacity-1000 buffer with no concurrent drain: all fit.
	if r.Len()+int(r.TotalDropped()) != 1000 {
		t.Errorf("accounted %d events, want 1000", r.Len()+int(r.TotalDropped()))
	}
}
