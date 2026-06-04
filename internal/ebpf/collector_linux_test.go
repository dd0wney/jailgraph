//go:build linux && linux_integration

package ebpf

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/profile"
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

// TestEBPF_EnforceProfileFromRealTrace is the payoff check: a full-coverage eBPF
// trace must feed the profile generator's default-deny path. With the expanded
// nr→name table a simple program's syscalls should all resolve, so an ENFORCING
// (default-deny SCMP_ACT_ERRNO) allowlist is emitted that permits the observed
// syscalls. If any syscall is still number-only, the renderer must refuse to
// enforce (catching the footgun) rather than silently deny it.
func TestEBPF_EnforceProfileFromRealTrace(t *testing.T) {
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
		for range coll.Errors() {
		}
	}()

	b := profile.Behavior{RunID: "ebpf-cat", FullCoverage: true, Syscalls: map[string]bool{}}
	for e := range events {
		if e.Kind == collector.EventSyscall {
			b.Syscalls[e.SyscallName] = true
		}
	}
	_ = coll.Wait()

	data, err := profile.RenderSeccompOCI(b, profile.SeccompOptions{Enforce: true})
	if err != nil {
		// Acceptable ONLY if it's the safe refusal for unnamed syscalls.
		if strings.Contains(err.Error(), "recorded by number only") {
			t.Logf("enforce safely refused (expand nr→name table to enable): %v", err)
			return
		}
		t.Fatalf("unexpected enforce error: %v", err)
	}
	// Enforcing profile must be default-deny and permit the observed hot path.
	if !strings.Contains(string(data), "SCMP_ACT_ERRNO") {
		t.Error("enforcing profile should be default-deny (SCMP_ACT_ERRNO)")
	}
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &prof); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("default action = %q, want SCMP_ACT_ERRNO", prof.DefaultAction)
	}
	var allowed []string
	for _, r := range prof.Syscalls {
		if r.Action == "SCMP_ACT_ALLOW" {
			allowed = append(allowed, r.Names...)
		}
	}
	for _, want := range []string{"read", "write"} {
		found := false
		for _, a := range allowed {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("enforcing allowlist must permit observed %q", want)
		}
	}
	t.Logf("enforcing default-deny profile permits %d syscalls", len(allowed))
}
