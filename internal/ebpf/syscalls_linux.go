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
	// Hot-path + common startup/runtime syscalls the seccomp backend never sees.
	// Naming them makes full coverage legible AND lets enforce-mode allowlists
	// resolve real programs. Only syscalls present on both amd64 and arm64 are
	// listed (so this stays a single cross-arch file); the rest fall back to
	// "sys_<nr>" and, in enforce mode, cause a safe refusal.
	unix.SYS_READ:            "read",
	unix.SYS_WRITE:           "write",
	unix.SYS_CLOSE:           "close",
	unix.SYS_LSEEK:           "lseek",
	unix.SYS_MMAP:            "mmap",
	unix.SYS_MUNMAP:          "munmap",
	unix.SYS_MREMAP:          "mremap",
	unix.SYS_MPROTECT:        "mprotect",
	unix.SYS_MADVISE:         "madvise",
	unix.SYS_BRK:             "brk",
	unix.SYS_FSTAT:           "fstat",
	unix.SYS_NEWFSTATAT:      "newfstatat",
	unix.SYS_STATX:           "statx",
	unix.SYS_FUTEX:           "futex",
	unix.SYS_RT_SIGACTION:    "rt_sigaction",
	unix.SYS_RT_SIGPROCMASK:  "rt_sigprocmask",
	unix.SYS_RT_SIGRETURN:    "rt_sigreturn",
	unix.SYS_EXIT:            "exit",
	unix.SYS_EXIT_GROUP:      "exit_group",
	unix.SYS_GETRANDOM:       "getrandom",
	unix.SYS_SET_ROBUST_LIST: "set_robust_list",
	unix.SYS_SET_TID_ADDRESS: "set_tid_address",
	unix.SYS_RSEQ:            "rseq",
	unix.SYS_FCNTL:           "fcntl",
	unix.SYS_IOCTL:           "ioctl",
	unix.SYS_GETDENTS64:      "getdents64",
	unix.SYS_FACCESSAT:       "faccessat",
	unix.SYS_READLINKAT:      "readlinkat",
	unix.SYS_PRLIMIT64:       "prlimit64",
	unix.SYS_FADVISE64:       "fadvise64",
	unix.SYS_NANOSLEEP:       "nanosleep",
	unix.SYS_CLOCK_GETTIME:   "clock_gettime",
	unix.SYS_GETPID:          "getpid",
	unix.SYS_GETTID:          "gettid",
	unix.SYS_GETUID:          "getuid",
	unix.SYS_GETEUID:         "geteuid",
	unix.SYS_GETGID:          "getgid",
	unix.SYS_GETEGID:         "getegid",
	unix.SYS_SCHED_YIELD:     "sched_yield",
	unix.SYS_PPOLL:           "ppoll",
	unix.SYS_UNAME:           "uname",
	unix.SYS_SYSINFO:         "sysinfo",
	unix.SYS_DUP:             "dup",
	unix.SYS_DUP3:            "dup3",
	unix.SYS_PIPE2:           "pipe2",
}

func syscallName(nr int) string {
	if n, ok := nrToName[nr]; ok {
		return n
	}
	return fmt.Sprintf("sys_%d", nr)
}
