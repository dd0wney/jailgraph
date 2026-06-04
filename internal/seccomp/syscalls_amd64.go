//go:build linux && amd64

package seccomp

import (
	"golang.org/x/sys/unix"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// auditArch is the AUDIT_ARCH value the filter pins so a 32-bit or foreign-arch
// syscall (which would have different numbering) is rejected rather than
// misinterpreted.
const auditArch = unix.AUDIT_ARCH_X86_64

// archFlagged is the curated observe set for amd64. The hot path
// (read/write/mmap/futex/brk) is deliberately excluded: user-notify serialises
// the target on every trap, so flagging high-frequency syscalls would throttle
// it and overflow the ring. We flag only the rare, semantically-rich calls.
func archFlagged() []syscallSpec {
	return []syscallSpec{
		{unix.SYS_EXECVE, "execve", collector.EventExec},
		{unix.SYS_EXECVEAT, "execveat", collector.EventExec},
		{unix.SYS_CLONE, "clone", collector.EventSpawn},
		{unix.SYS_CLONE3, "clone3", collector.EventSpawn},
		{unix.SYS_FORK, "fork", collector.EventSpawn},
		{unix.SYS_VFORK, "vfork", collector.EventSpawn},
		{unix.SYS_OPEN, "open", collector.EventOpen},
		{unix.SYS_OPENAT, "openat", collector.EventOpen},
		{unix.SYS_OPENAT2, "openat2", collector.EventOpen},
		{unix.SYS_UNSHARE, "unshare", collector.EventJoinNS},
		{unix.SYS_SETNS, "setns", collector.EventJoinNS},
		{unix.SYS_CAPSET, "capset", collector.EventCap},
	}
}
