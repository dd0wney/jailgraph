// Package model defines the behavior-graph domain: the node and edge shapes
// that get written to graphdb, and the natural keys used to deduplicate and
// reconcile them.
//
// A natural key uniquely identifies a node by its *content*, independent of the
// graphdb-assigned id. It serves two jobs:
//
//   - Deduplication: graphdb exposes no server-side uniqueness for our labels,
//     so the ingest worker dedups client-side by natural key before writing.
//   - Reconciliation: the key is embedded as a node property and echoed back in
//     the (out-of-order, partial) batch response, letting the worker map each
//     created node back to the key that produced it.
//
// Keys are prefixed by type so distinct node kinds never collide in the worker's
// id-cache, even though graphdb labels already separate them.
package model

import (
	"strconv"
	"strings"
)

// Node and edge label / type constants. Centralised so the schema is defined in
// exactly one place.
const (
	LabelRun        = "Run"
	LabelProcess    = "Process"
	LabelBinary     = "Binary"
	LabelSyscall    = "Syscall"
	LabelFile       = "File"
	LabelCapability = "Capability"
	LabelNamespace  = "Namespace"

	EdgePartOf   = "PART_OF"
	EdgeSpawned  = "SPAWNED"
	EdgeExec     = "EXEC"
	EdgeInvoked  = "INVOKED"
	EdgeOpened   = "OPENED"
	EdgeHeldCap  = "HELD_CAP"
	EdgeJoinedNS = "JOINED_NS"
)

// RunKey identifies a single learning session.
func RunKey(runID string) string { return "run:" + runID }

// ProcessKey is scoped to a run because PIDs are only unique within one run and
// are reused over time. Cross-run process identity is intentionally not modeled.
func ProcessKey(runID string, pid int32) string {
	return "proc:" + runID + ":" + strconv.Itoa(int(pid))
}

// BinaryKey prefers the content hash; it falls back to the path when the binary
// could not be hashed. The fallback is marked so a hashed and an unhashed
// observation of the same path never silently merge into one node with
// ambiguous identity.
func BinaryKey(sha256, path string) string {
	if sha256 != "" {
		return "bin:sha:" + sha256
	}
	return "bin:path:" + path
}

// SyscallKey identifies a syscall by number (stable within an architecture).
func SyscallKey(nr int) string { return "sys:" + strconv.Itoa(nr) }

// FileKey identifies a file by absolute path.
func FileKey(path string) string { return "file:" + path }

// CapKey identifies a Linux capability by name (e.g. "CAP_SYS_ADMIN").
func CapKey(name string) string { return "cap:" + name }

// NSKey identifies a namespace by type and inode-style id.
func NSKey(nsType string, id uint64) string {
	return "ns:" + nsType + ":" + strconv.FormatUint(id, 10)
}

// KeyKind returns the type prefix of a natural key ("bin", "sys", ...), used to
// route a key to the correct label when rebuilding the id-cache from the server.
func KeyKind(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return key
}
