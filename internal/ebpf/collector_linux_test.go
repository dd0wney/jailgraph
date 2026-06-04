//go:build linux && linux_integration

package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// TestEBPF_FullSyscallCoverage is the discriminating test for the eBPF backend:
// unlike the seccomp backend (which watches ~12 curated rare syscalls), the eBPF
// sys_enter tracepoint must observe the FULL syscall set — dozens of distinct
// syscalls including the read/write hot path. Requires a Linux kernel with BTF +
// raw-tracepoint support and CAP_BPF (run privileged in CI/Docker).
func TestEBPF_FullSyscallCoverage(t *testing.T) {
	// Trace /bin/cat directly: v1.0 follows only the seeded PID (descendant
	// following is v1.1), so the target must make the syscalls itself. cat reads
	// the file and writes it out — exercising the read/write hot path the
	// seccomp backend can't observe. Run the container with --pid=host so the
	// BPF root-ns PID matches the seeded PID (on a real host they always match).
	coll, err := NewCollector("/bin/cat", []string{"/etc/hostname"}, Config{})
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	defer coll.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	seen := map[string]bool{}
	var total int
	for e := range events {
		if e.Kind == collector.EventSyscall {
			total++
			seen[e.SyscallName] = true
		}
	}
	_ = coll.Wait()

	// Full coverage: even a trivial `cat` makes ~17 distinct syscalls. The
	// threshold is conservative to absorb the startup race (the earliest few
	// syscalls land before the PID is seeded); the hot-path assertion below is
	// the real discriminator vs the seccomp backend.
	if len(seen) < 12 {
		t.Errorf("expected full syscall coverage (>=12 distinct), got %d: %v", len(seen), keysOf(seen))
	}
	// The hot path the seccomp backend can never see must be present.
	for _, hot := range []string{"read", "write", "mmap"} {
		if !seen[hot] {
			t.Errorf("expected hot-path syscall %q in eBPF coverage (seccomp can't see it); got %v", hot, keysOf(seen))
		}
	}
	t.Logf("eBPF observed %d distinct syscalls across %d events", len(seen), total)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
