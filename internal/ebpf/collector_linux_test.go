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
func TestEBPF_TreeCoverageAndSpawn(t *testing.T) {
	// Trace a process TREE, not a single process: sh forks+execs cat. v1.1
	// descendant-following must capture cat's syscalls (read/write of the file)
	// even though only sh was launched — that's the discriminator vs v1.0 (which
	// saw only the seeded PID). Also asserts a SPAWNED sh->cat edge with the real
	// child pid. Run with --pid=host so BPF root-ns tgids match (real host always
	// matches).
	coll, err := NewCollector("/bin/sh", []string{"-c", "cat /etc/hostname >/dev/null"}, Config{})
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
	var spawns int
	var lastSpawnChild, lastSpawnParent int32
	for e := range events {
		switch e.Kind {
		case collector.EventSyscall:
			seen[e.SyscallName] = true
		case collector.EventSpawn:
			spawns++
			lastSpawnChild, lastSpawnParent = e.PID, e.PPID
		}
	}
	_ = coll.Wait()

	// read/write come from CAT (a descendant). Their presence proves
	// descendant-following — they would be absent in v1.0 (seeded-PID-only).
	for _, hot := range []string{"read", "write"} {
		if !seen[hot] {
			t.Errorf("expected descendant (cat) hot-path syscall %q; got %v", hot, keysOf(seen))
		}
	}
	if len(seen) < 12 {
		t.Errorf("expected full tree coverage (>=12 distinct), got %d: %v", len(seen), keysOf(seen))
	}
	// At least one SPAWNED edge (sh -> cat) with a real child pid.
	if spawns == 0 {
		t.Error("expected at least one SPAWN event (sh forking cat)")
	} else if lastSpawnChild == 0 || lastSpawnParent == 0 {
		t.Errorf("SPAWN event missing pids: child=%d parent=%d", lastSpawnChild, lastSpawnParent)
	}
	t.Logf("eBPF tree: %d distinct syscalls, %d spawns (last %d->%d)", len(seen), spawns, lastSpawnParent, lastSpawnChild)
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
