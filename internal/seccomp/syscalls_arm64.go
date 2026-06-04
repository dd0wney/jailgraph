//go:build linux && arm64

package seccomp

import (
	"golang.org/x/sys/unix"

	"github.com/dd0wney/jailgraph/internal/collector"
)

const auditArch = unix.AUDIT_ARCH_AARCH64

// archFlagged is the curated observe set for arm64. Note the arch lacks the
// legacy open/fork/vfork syscalls (everything goes through openat/clone), so
// they are absent here — a concrete reason the per-arch split is required.
func archFlagged() []syscallSpec {
	return []syscallSpec{
		{unix.SYS_EXECVE, "execve", collector.EventExec},
		{unix.SYS_EXECVEAT, "execveat", collector.EventExec},
		{unix.SYS_CLONE, "clone", collector.EventSpawn},
		{unix.SYS_CLONE3, "clone3", collector.EventSpawn},
		{unix.SYS_OPENAT, "openat", collector.EventOpen},
		{unix.SYS_OPENAT2, "openat2", collector.EventOpen},
		{unix.SYS_UNSHARE, "unshare", collector.EventJoinNS},
		{unix.SYS_SETNS, "setns", collector.EventJoinNS},
		{unix.SYS_CAPSET, "capset", collector.EventCap},
	}
}
