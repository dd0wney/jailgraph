// SPDX-License-Identifier: GPL-2.0
// jailgraph eBPF collector.
//
// v1.0: full syscall coverage for a tracked PID set (sys_enter -> seen bitmap).
// v1.1a: descendant following + race-free seeding + SPAWN events.
//
// Race-free seeding (no wrapper needed): userspace records ITS OWN tgid in
// `launcher` before forking the target. The target is born as jailgraph's child,
// so sched_process_fork adds it to `tracked` at fork time — before its first
// syscall. The launcher itself is never in `tracked`, so its syscalls are not
// recorded; only its descendants are. Keyed by tgid so the launcher's own
// threads (same tgid) are never mistaken for new processes.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EVENT_SPAWN 1
#define EVENT_EXEC 2

struct event {
	__u32 kind;
	__u32 pid;  // subject (child for SPAWN)
	__u32 ppid; // parent
	char path[256];
};

// launcher: single-entry array holding jailgraph's tgid (the tree root's parent).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} launcher SEC(".maps");

// tracked: the process subtree under the target (NOT including the launcher).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

// seen: which (tgid, syscall_nr) pairs occurred — read out at teardown.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, __u64);
	__type(value, __u8);
} seen SEC(".maps");

// events: streams SPAWN/EXEC/OPEN records to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	long nr = (long)ctx->args[1];
	__u64 key = ((__u64)tgid << 32) | (__u32)nr;
	__u8 one = 1;
	bpf_map_update_elem(&seen, &key, &one, BPF_ANY);
	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int handle_fork(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	__u32 ptgid = BPF_CORE_READ(parent, tgid);
	__u32 ctgid = BPF_CORE_READ(child, tgid);

	// Thread creation (same tgid) is not a new process — ignore.
	if (ctgid == ptgid)
		return 0;

	__u32 zero = 0;
	__u32 *launch = bpf_map_lookup_elem(&launcher, &zero);
	int parent_tracked = bpf_map_lookup_elem(&tracked, &ptgid) != NULL;
	int parent_is_launcher = launch && *launch == ptgid;
	if (!parent_tracked && !parent_is_launcher)
		return 0;

	__u8 one = 1;
	bpf_map_update_elem(&tracked, &ctgid, &one, BPF_ANY);

	// Emit a SPAWN edge only for real in-tree parents (not the launcher, which
	// is not part of the user's process graph).
	if (parent_tracked) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->kind = EVENT_SPAWN;
			e->pid = ctgid;
			e->ppid = ptgid;
			e->path[0] = 0;
			bpf_ringbuf_submit(e, 0);
		}
	}
	return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int handle_exec(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;

	// args: (task_struct *p, pid_t old_pid, struct linux_binprm *bprm).
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	const char *filename = BPF_CORE_READ(bprm, filename);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_EXEC;
	e->pid = tgid;
	e->ppid = 0;
	e->path[0] = 0;
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
