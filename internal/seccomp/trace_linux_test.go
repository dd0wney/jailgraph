//go:build linux && linux_integration

package seccomp

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/audit"
	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/profile"
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

// traceBehavior runs /bin/sh with args under the real seccomp collector and
// reduces the observed events to a profile.Behavior.
func traceBehavior(t *testing.T, args ...string) profile.Behavior {
	t.Helper()
	coll, err := NewSupervisor("/bin/sh", args, Config{})
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
		for range coll.Errors() {
		}
	}()
	b := profile.Behavior{Syscalls: map[string]bool{}}
	files, bins := map[string]struct{}{}, map[string]struct{}{}
	for e := range events {
		if e.SyscallName != "" {
			b.Syscalls[e.SyscallName] = true
		}
		switch e.Kind {
		case collector.EventOpen:
			if e.Path != "" {
				files[e.Path] = struct{}{}
			}
		case collector.EventExec:
			if e.Exe != "" {
				bins[e.Exe] = struct{}{}
			}
		}
	}
	_ = coll.Wait()
	for f := range files {
		b.Files = append(b.Files, f)
	}
	for bn := range bins {
		b.Binaries = append(b.Binaries, bn)
	}
	sort.Strings(b.Files)
	sort.Strings(b.Binaries)
	return b
}

// TestTrace_DriftAuditSuppressesVolatilePaths is the discriminating test the
// advisor flagged: two real traces of a program that touches a fresh temp file
// each run must NOT register as drift. The raw temp paths differ run-to-run; the
// audit's normalization must suppress them while the stable dimensions match.
func TestTrace_DriftAuditSuppressesVolatilePaths(t *testing.T) {
	const cmd = `d=$(mktemp); cat /etc/hostname > "$d"; rm "$d"`
	b1 := traceBehavior(t, "-c", cmd)
	b2 := traceBehavior(t, "-c", cmd)

	// Sanity: the two runs really did open different raw temp paths (otherwise
	// the test isn't exercising normalization).
	if rawEqual(b1.Files, b2.Files) {
		t.Logf("note: raw file sets were identical (%v); normalization not exercised", b1.Files)
	}

	r := audit.Diff(b1, b2)
	if r.DriftDetected(audit.ModeSecurity) {
		t.Errorf("two identical commands show drift:\n%s", r.RenderText(audit.ModeSecurity))
	}
	if len(r.Files.Added) != 0 || len(r.Files.Removed) != 0 {
		t.Errorf("normalized file drift should be empty; got added=%v removed=%v", r.Files.Added, r.Files.Removed)
	}
}

func rawEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
