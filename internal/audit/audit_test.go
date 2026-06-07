package audit

import (
	"strings"
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

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		// Volatile prefixes bucket to a single token (incl. the bare prefix).
		"/tmp":              "/tmp/*",
		"/tmp/build-aaa111": "/tmp/*",
		"/proc/1234/status": "/proc/*",
		"/var/tmp/x":        "/var/tmp/*",
		"/dev/shm/sem.abc":  "/dev/shm/*",
		// Short version/arch numbers are PRESERVED (not masked).
		"/lib/x86_64-linux-gnu/libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/libfoo-2.35.so":         "/usr/lib/libfoo-2.35.so",
		// Long runs (pids/timestamps/random) outside volatile prefixes collapse.
		"/home/u/.cache/build-1717459200": "/home/u/.cache/build-#",
		// Edge inputs.
		"/":             "/",
		"":              "",
		"/etc/hostname": "/etc/hostname",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePath_DoesNotMaskVersionDriftInVerdict(t *testing.T) {
	// Two runs differ only by a library version — a file-dimension difference.
	// It may or may not show in the (informational) file section, but it must
	// NEVER drive the verdict in either mode.
	baseline := bSet([]string{"openat"}, []string{"/usr/lib/libc-2.31.so"}, []string{"/bin/x"})
	candidate := bSet([]string{"openat"}, []string{"/usr/lib/libc-2.35.so"}, []string{"/bin/x"})
	r := Diff(baseline, candidate)
	if r.DriftDetected(ModeSecurity) || r.DriftDetected(ModeReproducibility) {
		t.Error("a file-only difference must not drive the verdict")
	}
	// With the tightened regex, short versions survive, so the difference IS
	// visible in the informational file section.
	if r.Files.empty() {
		t.Error("expected the version difference to appear in the informational file section")
	}
}

func TestRenderText(t *testing.T) {
	baseline := bSet([]string{"openat"}, []string{"/etc/a"}, []string{"/bin/x"})
	candidate := bSet([]string{"openat", "setns"}, []string{"/etc/a"}, []string{"/bin/x", "/bin/y"})
	r := Diff(baseline, candidate)
	r.BaselineRuns = []string{"runA"}
	r.CandidateRun = "runB"

	out := r.RenderText(ModeSecurity)
	for _, want := range []string{
		"drift audit (mode: security)", "runA", "runB",
		"syscalls (high confidence)", "+ setns", // the added syscall
		"binaries (medium confidence)", "+ /bin/y",
		"files (LOW confidence", "DRIFT DETECTED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText missing %q in:\n%s", want, out)
		}
	}

	// No-drift verdict line.
	clean := Diff(baseline, baseline)
	if !strings.Contains(clean.RenderText(ModeReproducibility), "no drift in stable dimensions") {
		t.Error("expected the no-drift verdict line")
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
