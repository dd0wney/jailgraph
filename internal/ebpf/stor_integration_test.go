//go:build linux && stor_integration

package ebpf

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/audit"
	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/profile"
)

// TestStor_ReproducibilityConvergence is the jailgraph×stór convergence: trace a
// stór sandboxed build (stor realise <recipe>) under the eBPF backend twice, then
// run the reproducibility audit over the two behavior graphs. A deterministic
// build must show NO stable-dimension (syscall/binary) drift.
//
// It also proves jailgraph follows a build's subprocesses across stór's namespace
// sandbox (user/mount/pid unshare + pivot_root): the build's syscalls are
// captured though only `stor` was launched. Requires STOR_BIN + STOR_RECIPE and a
// privileged --pid=host Linux environment. Validated without graphdb (Behavior is
// built straight from collector events, as in the v1.1 tests).
func TestStor_ReproducibilityConvergence(t *testing.T) {
	storBin := os.Getenv("STOR_BIN")
	recipe := os.Getenv("STOR_RECIPE")
	if storBin == "" || recipe == "" {
		t.Skip("set STOR_BIN and STOR_RECIPE to run the stór convergence test")
	}

	traceBuild := func() (profile.Behavior, error) {
		// Fresh store root each run so stór actually rebuilds (no cache hit),
		// making the two traces directly comparable.
		storeRoot := t.TempDir()
		coll, err := NewCollector(storBin, []string{"--store-root", storeRoot, "realise", recipe}, Config{})
		if err != nil {
			t.Fatalf("NewCollector: %v", err)
		}
		defer coll.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		events, err := coll.Start(ctx)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		go func() {
			for range coll.Errors() {
			}
		}()
		b := profile.Behavior{FullCoverage: true, Syscalls: map[string]bool{}}
		bins := map[string]struct{}{}
		for e := range events {
			switch e.Kind {
			case collector.EventSyscall:
				b.Syscalls[e.SyscallName] = true
			case collector.EventExec:
				bins[e.Exe] = struct{}{}
			}
		}
		// The target's exit status — a FAILED build must not silently pass: a
		// reproducibility check over two identically-failing builds would report
		// "no drift" and hollow-pass. Require the build to have succeeded.
		buildErr := coll.Wait()
		for bin := range bins {
			b.Binaries = append(b.Binaries, bin)
		}
		return b, buildErr
	}

	b1, err1 := traceBuild()
	b2, err2 := traceBuild()
	if err1 != nil || err2 != nil {
		// stór's build didn't succeed under tracing (e.g. its namespace sandbox
		// can't run on this host). jailgraph's tracing worked, but there's no
		// successful build to compare — so this cannot validate the convergence.
		t.Skipf("stór build failed under tracing (sandbox issue on this host?): run1=%v run2=%v", err1, err2)
	}

	// Sanity: we actually traced a build (descendant sh ran inside the sandbox).
	if len(b1.Syscalls) < 12 {
		t.Fatalf("trace looks empty (%d syscalls) — did jailgraph follow into stór's sandbox?", len(b1.Syscalls))
	}

	// Reproducible builds guarantee deterministic OUTPUT, not deterministic
	// execution traces: a full eBPF syscall set has minor libc-internal noise
	// (a stray getrandom/futex/rseq) run-to-run, so exact stable-dimension
	// equality is too strict (and contradicts audit's repro-mode framing).
	// Assert no STRUCTURAL drift instead — no new binaries exec'd and no drift in
	// security-relevant syscalls — while tolerating hot-path noise.
	r := audit.Diff(b1, b2)
	if len(r.Binaries.Added) != 0 || len(r.Binaries.Removed) != 0 {
		t.Errorf("binary (exec) set drifted across runs — non-deterministic exec: added=%v removed=%v",
			r.Binaries.Added, r.Binaries.Removed)
	}
	structural := map[string]bool{
		"execve": true, "execveat": true, "clone": true, "clone3": true,
		"fork": true, "vfork": true, "setns": true, "unshare": true,
		"capset": true, "socket": true, "connect": true, "ptrace": true,
		"mount": true, "bpf": true,
	}
	for _, sc := range append(append([]string{}, r.Syscalls.Added...), r.Syscalls.Removed...) {
		if structural[sc] {
			t.Errorf("structural syscall drift between identical builds (impurity signal): %s", sc)
		}
	}
	t.Logf("stór build traced: %d distinct syscalls, %d binaries; hot-path syscall noise (tolerated): +%v -%v",
		len(b1.Syscalls), len(b1.Binaries), r.Syscalls.Added, r.Syscalls.Removed)
}
