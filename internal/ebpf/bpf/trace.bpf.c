// SPDX-License-Identifier: GPL-2.0
// jailgraph eBPF collector — v1.0: full syscall coverage, scoped to a tracked
// PID set.
//
// This is the headline advantage over the seccomp backend: a raw tracepoint on
// sys_enter sees EVERY syscall (including the read/write/mmap hot path the
// seccomp backend deliberately skips), in-kernel, with negligible cost — we
// record each (pid, syscall_nr) once in a hash map and read the set out at
// teardown rather than streaming every call.
//
// Scope: userspace seeds the `tracked` map with the target's PID. (Descendant
// following via sched_process_fork, plus exec/open detail, are layered on next
// using CO-RE.)

// vmlinux.h is generated from the kernel's BTF (see `make bpf-generate`); it is
// self-contained (no libc/asm headers) and defines every kernel type, which is
// why CO-RE BPF programs use it instead of <linux/bpf.h>.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// tracked: the set of PIDs we observe (target + descendants). Seeded by
// userspace; value is an unused marker.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

// seen: which (pid, syscall_nr) pairs occurred. Key packs pid<<32 | nr. Read by
// userspace at teardown to recover the full per-pid syscall set.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, __u64);
	__type(value, __u8);
} seen SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &pid))
		return 0; // not in our process subtree

	// For sys_enter, args[0] is pt_regs*, args[1] is the syscall number.
	long nr = (long)ctx->args[1];
	__u64 key = ((__u64)pid << 32) | (__u32)nr;
	__u8 one = 1;
	bpf_map_update_elem(&seen, &key, &one, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
