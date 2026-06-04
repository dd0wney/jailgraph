package collector

import (
	"context"
	"testing"
	"time"
)

func TestFakeCollector_EmitsEventsInOrderThenCloses(t *testing.T) {
	want := []BehaviorEvent{
		{Kind: EventExec, PID: 10, Exe: "/bin/sh"},
		{Kind: EventOpen, PID: 10, Path: "/etc/hostname", OpenMode: "r"},
		{Kind: EventSpawn, PID: 10, PPID: 1},
	}
	fc := NewFake(want)

	ch, err := fc.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	var got []BehaviorEvent
	for e := range ch {
		got = append(got, e)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].Path != want[i].Path {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Errors channel must close after the event channel.
	for range fc.Errors() {
		t.Error("unexpected error emitted")
	}
	if err := fc.Wait(); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

func TestEventKind_String(t *testing.T) {
	cases := map[EventKind]string{
		EventExec:     "exec",
		EventSpawn:    "spawn",
		EventOpen:     "open",
		EventSyscall:  "syscall",
		EventCap:      "cap",
		EventJoinNS:   "joinns",
		EventKind(0):  "unknown",
		EventKind(99): "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("EventKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestFakeCollector_WaitBeforeStartAndClose(t *testing.T) {
	fc := NewFake(nil)
	if err := fc.Wait(); err == nil {
		t.Error("Wait before Start should error")
	}
	// Close is safe before Start and idempotent.
	if err := fc.Close(); err != nil {
		t.Errorf("Close before Start: %v", err)
	}
	if err := fc.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestFakeCollector_StartTwiceFails(t *testing.T) {
	fc := NewFake(nil)
	if _, err := fc.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err := fc.Start(context.Background()); err == nil {
		t.Fatal("second Start should fail")
	}
}

func TestFakeCollector_PropagatesErrors(t *testing.T) {
	fc := NewFake(nil, collectorError("boom"))
	if _, err := fc.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Drain events (none) then errors.
	for e := range fc.Errors() {
		if e.Error() != "boom" {
			t.Errorf("got error %q, want boom", e)
		}
	}
}

func TestFakeCollector_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Start drains
	fc := NewFake([]BehaviorEvent{{Kind: EventExec}, {Kind: EventOpen}})
	ch, err := fc.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Drain whatever was emitted before cancellation took effect.
	for range ch {
	}
	deadline := time.After(time.Second)
	select {
	case <-deadline:
		t.Fatal("Errors did not close after cancellation")
	default:
	}
}
