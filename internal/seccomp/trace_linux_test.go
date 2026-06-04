//go:build linux && linux_integration

package seccomp

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// TestMain replicates the real jailgraph binary's entrypoint: the supervisor
// re-execs os.Executable() and expects MaybeRunChild() to run first. The test
// binary's normal entrypoint is the test harness, which would never enter child
// mode — so without this, the re-exec'd child re-runs the tests and the parent
// blocks forever waiting for the notify fd.
func TestMain(m *testing.M) {
	if handled, err := MaybeRunChild(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "traced child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestTrace_RealTarget runs a real seccomp-notify trace of a short command and
// asserts that the expected behavior is observed. It is build-tagged
// (linux_integration) because it requires a Linux kernel with seccomp
// user-notify (>= 5.0); it runs unprivileged via the no_new_privs path.
//
// This is the test that would have caught a missing runtime.LockOSThread() in
// runChild: without the lock the execve can run on an unfiltered thread and the
// event stream comes back empty.
func TestTrace_RealTarget(t *testing.T) {
	coll, err := NewSupervisor("/bin/sh", []string{"-c", "cat /etc/hostname >/dev/null"}, Config{})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	defer coll.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, err := coll.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	go func() {
		for e := range coll.Errors() {
			t.Logf("collector error: %v", e)
		}
	}()

	var sawExec, sawOpenHostname bool
	var total int
	for e := range events {
		total++
		switch e.Kind {
		case collector.EventExec:
			sawExec = true
		case collector.EventOpen:
			if e.Path == "/etc/hostname" {
				sawOpenHostname = true
			}
		}
	}
	_ = coll.Wait()

	if total == 0 {
		t.Fatal("observed zero events — filter likely attached to the wrong thread (check runtime.LockOSThread in runChild)")
	}
	if !sawExec {
		t.Error("expected at least one EventExec (the cat exec)")
	}
	if !sawOpenHostname {
		t.Error("expected an EventOpen for /etc/hostname")
	}
}
