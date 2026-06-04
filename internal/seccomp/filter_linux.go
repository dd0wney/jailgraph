//go:build linux

package seccomp

import "golang.org/x/sys/unix"

// Offsets into struct seccomp_data, which is what the classic-BPF filter sees.
const (
	offsetNr   = 0 // int nr
	offsetArch = 4 // __u32 arch
)

// buildFilter assembles a classic-BPF program that:
//  1. pins the architecture (a foreign/32-bit syscall has different numbering,
//     so it is killed rather than misread), then
//  2. returns SECCOMP_RET_USER_NOTIF for each flagged syscall, and
//  3. returns SECCOMP_RET_ALLOW for everything else (the target runs normally;
//     only the rare flagged calls trap to the supervisor).
//
// This is observation, not enforcement: nothing is ever denied here.
func buildFilter(nrs []int) []unix.SockFilter {
	prog := []unix.SockFilter{
		// A = seccomp_data.arch
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offsetArch),
		// if A == auditArch: continue; else kill the process.
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(auditArch), 1, 0),
		bpfStmt(unix.BPF_RET|unix.BPF_K, retKillProcess),
		// A = seccomp_data.nr
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offsetNr),
	}
	// For each flagged nr: if A == nr return USER_NOTIF.
	for _, nr := range nrs {
		prog = append(prog,
			bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(nr), 0, 1),
			bpfStmt(unix.BPF_RET|unix.BPF_K, retUserNotif),
		)
	}
	// Default: allow.
	prog = append(prog, bpfStmt(unix.BPF_RET|unix.BPF_K, retAllow))
	return prog
}

// Return-action constants (uint32 K values for BPF_RET).
const (
	retAllow       = uint32(unix.SECCOMP_RET_ALLOW)
	retUserNotif   = uint32(unix.SECCOMP_RET_USER_NOTIF)
	retKillProcess = uint32(unix.SECCOMP_RET_KILL_PROCESS)
)

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
