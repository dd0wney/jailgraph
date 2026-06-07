// Package collector defines the stable contract between behavior observation and
// everything downstream (buffering, ingestion, the graph schema).
//
// A Collector observes a single target program and emits fully *decoded*
// BehaviorEvents. The decoding boundary is deliberate: by emitting semantic
// events (an "exec of /bin/sh", an "open of /etc/hostname") rather than raw
// kernel syscall structs, a future eBPF backend can satisfy this same interface
// without any change to the buffer, the ingest worker, or the schema. The
// seccomp user-notify backend is simply the first implementation.
//
// Nothing in this package imports OS-specific syscall machinery, so it builds
// and tests on every platform. The Linux-locked code lives in internal/seccomp.
package collector

import (
	"context"
	"time"
)

// EventKind classifies a BehaviorEvent. Each kind maps to one edge type in the
// behavior graph (see internal/model).
type EventKind uint8

const (
	// EventExec is an execve/execveat: the process replaced its image with a
	// binary. Maps to an EXEC edge (Process -> Binary).
	EventExec EventKind = iota + 1
	// EventSpawn is a clone/fork/vfork that created a child process. Maps to a
	// SPAWNED edge (Process -> Process).
	EventSpawn
	// EventOpen is an open/openat/openat2 of a file path. Maps to an OPENED
	// edge (Process -> File).
	EventOpen
	// EventSyscall is any flagged syscall invocation, aggregated downstream into
	// a per-(process, syscall) count. Maps to an INVOKED edge (Process -> Syscall).
	EventSyscall
	// EventCap is a capset that asserted a capability. Maps to a HELD_CAP edge
	// (Process -> Capability).
	EventCap
	// EventJoinNS is an unshare/setns that joined a namespace. Maps to a
	// JOINED_NS edge (Process -> Namespace).
	EventJoinNS
	// EventFileActivity is a per-(run, file) write/rename/unlink summary, emitted
	// once at teardown after the backend folds raw write/rename/unlink activity
	// across the process tree. Maps to a per-run FileActivity node (no acting
	// process — it is a run-level aggregate). The fields below carry its counts.
	EventFileActivity
)

// String returns a stable lowercase name for the kind, used to label drop
// counters on the Run node.
func (k EventKind) String() string {
	switch k {
	case EventExec:
		return "exec"
	case EventSpawn:
		return "spawn"
	case EventOpen:
		return "open"
	case EventSyscall:
		return "syscall"
	case EventCap:
		return "cap"
	case EventJoinNS:
		return "joinns"
	case EventFileActivity:
		return "fileio"
	default:
		return "unknown"
	}
}

// BehaviorEvent is one decoded observation about the target. It is backend
// agnostic: the seccomp and (future) eBPF collectors both produce these.
//
// Only the fields relevant to Kind are populated; the rest are zero values.
// The struct is intentionally flat (no nested pointers) so it is cheap to copy
// through the ring buffer and trivially comparable in tests.
type BehaviorEvent struct {
	Kind      EventKind
	PID       int32
	PPID      int32
	Timestamp time.Time

	// Process / exec identity (EventExec, EventSpawn).
	Exe     string
	Cmdline []string
	UID     uint32

	// Binary identity (EventExec). BinSHA256 is best-effort; it is empty when the
	// binary could not be hashed (e.g. unreadable), never a fabricated value.
	BinSHA256 string

	// Syscall identity (EventSyscall and, redundantly, every other kind so the
	// raw syscall is always recoverable).
	SyscallNr   int
	SyscallName string

	// File access (EventOpen). Path is resolved TOCTOU-safely by the backend;
	// OpenMode is the decoded access intent ("r", "rw", "create", ...).
	Path     string
	OpenMode string

	// Capability (EventCap).
	CapName string

	// Namespace (EventJoinNS).
	NSType string
	NSID   uint64

	// File I/O aggregate (EventFileActivity). Populated only for that kind; Path
	// carries the file path. Counts are run-level (folded across the process tree
	// at teardown). Entropy is the Shannon entropy (bits/byte, 0..8) of a sample
	// of the written content — the ransomware encryption signal; 0 when the
	// backend captured no content (eBPF-only; macOS ES exposes no write content).
	WriteCount  int64
	Bytes       int64
	RenameCount int64
	UnlinkCount int64
	Entropy     float64

	// Lossy is true when the producing pipeline dropped events before this one.
	// It propagates to the Run node so a generated profile is never silently
	// treated as complete when it was built from a truncated trace.
	Lossy bool
}

// Collector observes one target program's behavior.
//
// Lifecycle: Start installs instrumentation and launches the target, returning a
// channel of decoded events. The channel is closed exactly once when collection
// ends (target exit or ctx cancellation). Fatal setup failures (e.g. the kernel
// rejects the seccomp filter, or the platform is unsupported) are returned
// synchronously from Start. Non-fatal, mid-run problems (a decode that failed
// its TOCTOU revalidation, say) are reported on Errors() and never silently
// swallowed.
type Collector interface {
	// Start installs instrumentation, launches the target, and returns the event
	// stream. It must be called at most once per Collector.
	Start(ctx context.Context) (<-chan BehaviorEvent, error)

	// Errors returns the channel of non-fatal observation errors. Callers should
	// drain it; it is closed when the event channel is.
	Errors() <-chan error

	// Wait blocks until the target has exited and returns the cause (nil on a
	// clean exit). It is valid to call only after Start.
	Wait() error

	// Close releases instrumentation resources. It is safe to call more than once.
	Close() error
}
