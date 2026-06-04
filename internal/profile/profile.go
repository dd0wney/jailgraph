// Package profile turns an observed behavior graph (one Run) into sandbox
// profiles: a firejail profile and an OCI-style seccomp profile.
//
// Honesty about strength (this matters — an over-claimed profile breaks programs
// or gives false confidence):
//
//   - The firejail FILESYSTEM + EXEC whitelist is genuinely evidence-based: it
//     lists exactly the files the program opened and the binaries it exec'd.
//     This is jailgraph's real value-add over a generic profile.
//   - The seccomp syscall policy is NOT a least-privilege allowlist. The
//     collector observes only a curated set of rare, security-relevant syscalls
//     (never the hot path), so we cannot know the full syscall set. Instead we
//     take a permissive baseline and DENY the dangerous syscalls the program
//     demonstrably never used ("baseline minus unobserved-dangerous"). A tight
//     allowlist needs the eBPF backend's full coverage (a later increment).
//   - Capability/namespace policy is NOT emitted from observation: increment 1
//     does not yet decode capset/setns into Capability/Namespace nodes. firejail
//     output uses a conservative `caps.drop all` DEFAULT, clearly labeled as a
//     default rather than evidence.
package profile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// GateableSyscalls is the set of dangerous, security-relevant syscalls the
// collector watches. The seccomp policy denies whichever of these the run never
// invoked. Kept in sync with internal/seccomp's flagged set, but defined here as
// portable strings so this package builds on every platform.
var GateableSyscalls = []string{
	"execve", "execveat",
	"clone", "clone3", "fork", "vfork",
	"open", "openat", "openat2",
	"unshare", "setns",
	"capset",
}

// Behavior is the observed surface of one run, reduced to what the profiles
// need. Caps/Namespaces are intentionally absent (not yet decoded).
type Behavior struct {
	RunID    string
	Target   string
	Syscalls map[string]bool // observed syscall names
	Files    []string        // observed opened paths
	Binaries []string        // observed exec'd binary paths
	Lossy    bool            // the trace dropped events; profile is unsafe
	// FullCoverage is true only when the collector observed the COMPLETE syscall
	// set (eBPF). It gates default-deny (least-privilege) seccomp generation: a
	// default-deny profile from partial coverage would deny syscalls the program
	// actually needs.
	FullCoverage bool
}

// DeniedSyscalls returns the gateable syscalls the run never invoked — the ones
// the seccomp policy denies. Sorted for deterministic output.
func (b Behavior) DeniedSyscalls() []string {
	var denied []string
	for _, sc := range GateableSyscalls {
		if !b.Syscalls[sc] {
			denied = append(denied, sc)
		}
	}
	sort.Strings(denied)
	return denied
}

// ociSeccomp is the subset of the OCI runtime-spec seccomp schema we emit.
type ociSeccomp struct {
	DefaultAction string            `json:"defaultAction"`
	Architectures []string          `json:"architectures,omitempty"`
	Syscalls      []ociSyscallRule  `json:"syscalls"`
	Comment       map[string]string `json:"_comment,omitempty"`
}

type ociSyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// SeccompOptions tunes seccomp rendering.
type SeccompOptions struct {
	// Enforce requests an enforcing (SCMP_ACT_ERRNO default) least-privilege
	// profile instead of the safe complain-mode (SCMP_ACT_LOG) default. Honored
	// only for full-coverage runs, and refused when the trace is lossy or any
	// observed syscall is unnamed (which would be wrongly denied).
	Enforce bool
}

// RenderSeccompOCI emits an OCI seccomp profile, choosing the construction by
// coverage:
//   - Partial coverage (seccomp backend): default-ALLOW minus the dangerous
//     syscalls the run never used. NOT a least-privilege allowlist.
//   - Full coverage (eBPF backend): a least-privilege allowlist (default-deny).
//     Defaults to complain mode (SCMP_ACT_LOG) — safe to deploy, breaks nothing,
//     logs would-be denials — with enforcing mode gated behind opts.Enforce.
func RenderSeccompOCI(b Behavior, opts SeccompOptions) ([]byte, error) {
	if !b.FullCoverage {
		return renderGatingSeccomp(b), nil
	}
	return renderAllowlistSeccomp(b, opts)
}

// renderGatingSeccomp is the partial-coverage profile (default-allow + gating).
func renderGatingSeccomp(b Behavior) []byte {
	denied := b.DeniedSyscalls()
	prof := ociSeccomp{
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls:      []ociSyscallRule{},
		Comment: map[string]string{
			"generated_by": "jailgraph",
			"run":          b.RunID,
			"strength":     "baseline-allow minus dangerous-syscall gating; NOT a least-privilege allowlist (partial syscall coverage). Trace with the eBPF collector for a tight allowlist.",
		},
	}
	if len(denied) > 0 {
		prof.Syscalls = append(prof.Syscalls, ociSyscallRule{Names: denied, Action: "SCMP_ACT_ERRNO"})
	}
	data, _ := json.MarshalIndent(prof, "", "  ")
	return data
}

// renderAllowlistSeccomp is the full-coverage least-privilege profile. Allow =
// the observed syscalls UNION the safe runtime floor. Default action is LOG
// (complain) unless enforcing is explicitly requested and safe.
func renderAllowlistSeccomp(b Behavior, opts SeccompOptions) ([]byte, error) {
	var unnamed []string
	allow := map[string]struct{}{}
	for sc := range b.Syscalls {
		if isUnnamed(sc) {
			unnamed = append(unnamed, sc) // recorded by number only — can't allowlist by name
			continue
		}
		allow[sc] = struct{}{}
	}
	// The safe floor papers over v1.0 coverage holes (startup race, missed
	// children/error paths). It contains only universal runtime syscalls and
	// excludes every dangerous/gateable one, so it never re-permits what gating
	// would deny.
	for _, sc := range baselineFloor {
		allow[sc] = struct{}{}
	}

	defaultAction := "SCMP_ACT_LOG"
	mode := "complain (SCMP_ACT_LOG): enforces nothing, logs would-be denials. Validate coverage, then regenerate with --enforce."
	if opts.Enforce {
		if b.Lossy {
			return nil, fmt.Errorf("refusing to enforce: run %s was lossy (incomplete trace)", b.RunID)
		}
		if len(unnamed) > 0 {
			sort.Strings(unnamed)
			return nil, fmt.Errorf("refusing to enforce: %d observed syscalls are recorded by number only and would be wrongly denied (%s); complete the nr→name table or use complain mode", len(unnamed), strings.Join(unnamed, ","))
		}
		defaultAction = "SCMP_ACT_ERRNO"
		mode = "ENFORCING (SCMP_ACT_ERRNO). Built from observed runs; validate coverage (children, error/signal paths) before production. Prefer a union of representative runs."
	}

	prof := ociSeccomp{
		DefaultAction: defaultAction,
		Syscalls:      []ociSyscallRule{{Names: sortedKeys(allow), Action: "SCMP_ACT_ALLOW"}},
		Comment: map[string]string{
			"generated_by": "jailgraph",
			"run":          b.RunID,
			"strength":     "least-privilege allowlist from full (eBPF) syscall coverage + a safe runtime floor",
			"mode":         mode,
		},
	}
	return json.MarshalIndent(prof, "", "  ")
}

func isUnnamed(name string) bool { return strings.HasPrefix(name, "sys_") }

// baselineFloor is the set of universal runtime syscalls a default-deny profile
// must permit so it does not break on startup/coverage holes. It deliberately
// contains NO dangerous/gateable syscall (no execve, clone, setns, unshare,
// capset, ptrace, mount, bpf, ...), so it never undoes the point of an
// allowlist. It shrinks toward empty as coverage improves.
var baselineFloor = []string{
	"read", "write", "close", "lseek", "fstat", "newfstatat", "statx",
	"mmap", "munmap", "mremap", "mprotect", "madvise", "brk",
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
	"exit", "exit_group", "futex", "nanosleep", "clock_gettime", "clock_nanosleep",
	"getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
	"getrandom", "set_robust_list", "set_tid_address", "rseq",
	"sched_yield", "sched_getaffinity", "restart_syscall",
	"fcntl", "ioctl", "getdents64", "readlinkat", "faccessat", "faccessat2",
	"ppoll", "poll", "epoll_wait", "epoll_pwait", "epoll_create1", "epoll_ctl",
	"dup", "dup3", "pipe2", "uname", "sysinfo", "prlimit64", "arch_prctl",
}

// RenderFirejail emits a firejail .profile. Its filesystem/exec whitelist is
// evidence-based; the seccomp.drop line mirrors the OCI deny list; caps and net
// are conservative defaults, labeled as such.
func RenderFirejail(b Behavior) string {
	var sb strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&sb, format, a...); sb.WriteByte('\n') }

	w("# firejail profile generated by jailgraph for run %s (target: %s)", b.RunID, b.Target)
	if b.Lossy {
		w("# WARNING: trace was lossy — this profile is incomplete and may break the program.")
	}
	w("")

	w("# --- evidence-based filesystem whitelist (observed opens) ---")
	dirs := observedDirs(b.Files)
	if len(dirs) == 0 {
		w("# (no file opens observed)")
	}
	for _, d := range dirs {
		w("whitelist %s", d)
	}
	w("")

	w("# --- dangerous syscalls the program never used (denied) ---")
	denied := b.DeniedSyscalls()
	if len(denied) > 0 {
		w("seccomp.drop %s", strings.Join(denied, ","))
	} else {
		w("# (program used all watched syscalls; none denied)")
	}
	w("")

	w("# --- conservative DEFAULTS (not from observation) ---")
	w("# no capability evidence is collected yet; drop all by default.")
	w("caps.drop all")
	w("# no network syscalls are observed yet; assume none. Remove if the program needs net.")
	w("net none")
	w("nonewprivs")
	w("noroot")
	return sb.String()
}

// observedDirs reduces opened file paths to their parent directories, sorted and
// de-duplicated, for a compact firejail whitelist.
func observedDirs(files []string) []string {
	seen := map[string]struct{}{}
	for _, f := range files {
		if f == "" {
			continue
		}
		d := filepath.Dir(f)
		seen[d] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
