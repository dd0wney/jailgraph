package audit

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/profile"
)

func bSet(syscalls []string, files, bins []string) profile.Behavior {
	m := map[string]bool{}
	for _, s := range syscalls {
		m[s] = true
	}
	return profile.Behavior{Syscalls: m, Files: files, Binaries: bins}
}

// The central test: benign per-run variation (volatile temp paths, differing
// pids) must NOT register as drift, while a genuinely new syscall must.
func TestDiff_VolatilePathsAreNotDriftButNewSyscallIs(t *testing.T) {
	baseline := bSet(
		[]string{"openat", "execve"},
		[]string{"/etc/hostname", "/tmp/build-aaa111", "/proc/1234/status"},
		[]string{"/bin/cat"},
	)
	candidate := bSet(
		[]string{"openat", "execve", "setns"},                               // setns is NEW — real drift
		[]string{"/etc/hostname", "/tmp/build-bbb999", "/proc/5678/status"}, // different volatile paths
		[]string{"/bin/cat"},
	)
	r := Diff(baseline, candidate)

	// File drift must be empty after normalization (only volatile paths differed).
	if !r.Files.empty() {
		t.Errorf("normalized file drift should be empty, got added=%v removed=%v", r.Files.Added, r.Files.Removed)
	}
	// The new syscall must be detected.
	if len(r.Syscalls.Added) != 1 || r.Syscalls.Added[0] != "setns" {
		t.Errorf("expected setns as added syscall, got %v", r.Syscalls.Added)
	}
	if !r.DriftDetected(ModeSecurity) {
		t.Error("security mode should flag the new syscall")
	}
}

func TestDriftDetected_FileDriftNeverDrivesVerdict(t *testing.T) {
	// Identical stable dimensions; only (un-normalizable) file paths differ.
	baseline := bSet([]string{"openat"}, []string{"/etc/a"}, []string{"/bin/x"})
	candidate := bSet([]string{"openat"}, []string{"/etc/b"}, []string{"/bin/x"})
	r := Diff(baseline, candidate)
	if r.Files.empty() {
		t.Fatal("expected a file difference for this fixture")
	}
	if r.DriftDetected(ModeSecurity) || r.DriftDetected(ModeReproducibility) {
		t.Error("file drift must not drive the verdict in either mode")
	}
}

func TestDriftDetected_SecurityVsReproducibility(t *testing.T) {
	// Candidate did LESS (removed a syscall), no additions.
	baseline := bSet([]string{"openat", "setns"}, nil, nil)
	candidate := bSet([]string{"openat"}, nil, nil)
	r := Diff(baseline, candidate)

	// Security cares only about additive drift → no drift.
	if r.DriftDetected(ModeSecurity) {
		t.Error("security mode should ignore removed-only drift")
	}
	// Reproducibility cares about any symmetric drift → drift.
	if !r.DriftDetected(ModeReproducibility) {
		t.Error("reproducibility mode should flag removed syscall")
	}
}

func TestUnion_WidensBaseline(t *testing.T) {
	u := Union(
		bSet([]string{"openat"}, []string{"/a"}, []string{"/bin/x"}),
		bSet([]string{"clone"}, []string{"/b"}, []string{"/bin/y"}),
	)
	if !u.Syscalls["openat"] || !u.Syscalls["clone"] {
		t.Errorf("union missing syscalls: %v", u.Syscalls)
	}
	if len(u.Files) != 2 || len(u.Binaries) != 2 {
		t.Errorf("union files=%v binaries=%v", u.Files, u.Binaries)
	}
	// A candidate using only the second run's syscall must not drift against the union.
	r := Diff(u, bSet([]string{"clone"}, nil, nil))
	if r.Syscalls.additive() {
		t.Error("candidate within the union should not show additive syscall drift")
	}
}
