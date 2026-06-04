//go:build linux

package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// nrToName maps syscall numbers to names. To stay buildable on both amd64 and
// arm64 it references only syscalls present on every arch (so no legacy
// open/fork/vfork, which exist on amd64 only). Unknown numbers fall back to
// "sys_<nr>".
//
// This is a deliberately partial table for v1.0 — enough to name the
// security-relevant gateable syscalls (so the profile generator's gating works
// under the eBPF backend) plus common hot-path calls (so full-coverage is
// legible). A complete nr→name table is a follow-up.
var nrToName = map[int]string{
	unix.SYS_EXECVE:   "execve",
	unix.SYS_EXECVEAT: "execveat",
	unix.SYS_OPENAT:   "openat",
	unix.SYS_OPENAT2:  "openat2",
	unix.SYS_CLONE:    "clone",
	unix.SYS_CLONE3:   "clone3",
	unix.SYS_UNSHARE:  "unshare",
	unix.SYS_SETNS:    "setns",
	unix.SYS_CAPSET:   "capset",
	// Hot-path syscalls the seccomp backend never sees — naming them makes the
	// eBPF backend's full coverage visible.
	unix.SYS_READ:     "read",
	unix.SYS_WRITE:    "write",
	unix.SYS_CLOSE:    "close",
	unix.SYS_MMAP:     "mmap",
	unix.SYS_MPROTECT: "mprotect",
	unix.SYS_FUTEX:    "futex",
}

func syscallName(nr int) string {
	if n, ok := nrToName[nr]; ok {
		return n
	}
	return fmt.Sprintf("sys_%d", nr)
}
