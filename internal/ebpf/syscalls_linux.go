//go:build linux

package ebpf

import "fmt"

// syscallName resolves a syscall number to its name using the per-arch table in
// sysname_linux_<arch>.go (generated from golang.org/x/sys/unix). Unknown
// numbers fall back to "sys_<nr>" — which makes enforce-mode profile generation
// safely refuse rather than mis-deny.
func syscallName(nr int) string {
	if n, ok := nrToName[nr]; ok {
		return n
	}
	return fmt.Sprintf("sys_%d", nr)
}
