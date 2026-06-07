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
#include <bpf/bpf_tracing.h>

#define EVENT_SPAWN 1
#define EVENT_EXEC 2
#define EVENT_OPEN 3
#define EVENT_NS 4
#define EVENT_RENAME 5
#define EVENT_UNLINK 6

// FMODE_WRITE is a fmode_t bit (uapi, not a BTF type) — set when a file is
// opened for writing.
#define FMODE_WRITE 0x2

// Namespace-creation flags (CLONE_NEW*), not present in vmlinux.h (they are
// uapi #defines, not BTF types).
#define CLONE_NEWTIME 0x00000080
#define CLONE_NEWNS 0x00020000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000
#define CLONE_NEW_ALL (CLONE_NEWTIME | CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
		       CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

struct event {
	__u32 kind;
	__u32 pid;   // subject (child for SPAWN)
	__u32 ppid;  // parent
	__u32 flags; // NS: the CLONE_NEW* bits unshared; unused otherwise
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

// seen_caps: which (tgid, capability) checks occurred — read out at teardown.
// cap_capable fires on every permission check (high frequency), so we dedup in
// a map rather than streaming each check.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} seen_caps SEC(".maps");

// events: streams SPAWN/EXEC/OPEN/RENAME/UNLINK records to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct path_buf {
	char path[256];
};

// write_paths: inode -> resolved path, populated at open-for-write where
// bpf_d_path is allowlisted. The write hook (where bpf_d_path is NOT allowlisted)
// keys by inode only; userspace joins the two at teardown.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 14);
	__type(key, __u64);
	__type(value, struct path_buf);
} write_paths SEC(".maps");

// write_stats: inode -> aggregated write count + bytes. Like `seen`, the hot
// write path is folded IN-KERNEL (never streamed) and read out at teardown. The
// per-inode counter already folds writes across the tracked subtree (run-level).
// WRITE_SAMPLE_LEN bytes of the first sufficiently-large write are sampled per
// inode for userspace Shannon-entropy (the ransomware encryption signal).
#define WRITE_SAMPLE_LEN 256
struct write_stat {
	__u64 count;
	__u64 bytes;
	__u32 sample_len; // 0 until a write >= WRITE_SAMPLE_LEN is sampled
	__u8  sample[WRITE_SAMPLE_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 14);
	__type(key, __u64);
	__type(value, struct write_stat);
} write_stats SEC(".maps");

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
			e->flags = 0;
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
	e->flags = 0;
	e->path[0] = 0;
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// handle_open fires on every file open in a tracked process. We use an fentry
// on security_file_open (a BTF-typed hook) with bpf_d_path() — the blessed,
// allowlisted path-resolution helper — rather than reading the openat pathname
// arg from pt_regs (which uses the syscall, not function, calling convention and
// yields garbage). This gives fully-resolved absolute paths.
SEC("fentry/security_file_open")
int BPF_PROG(handle_open, struct file *file)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_OPEN;
	e->pid = tgid;
	e->ppid = 0;
	e->flags = 0;
	e->path[0] = 0;
	bpf_d_path(&file->f_path, e->path, sizeof(e->path));
	// If opened for write, remember inode -> path so handle_write (which cannot
	// call bpf_d_path) can attribute its byte counts by inode at teardown. The
	// value is copied straight from the ringbuf event's path buffer (e->path is a
	// 256-byte region, matching struct path_buf) to avoid a large stack copy.
	if (BPF_CORE_READ(file, f_mode) & FMODE_WRITE) {
		__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
		if (ino)
			bpf_map_update_elem(&write_paths, &ino, e->path, BPF_ANY);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// handle_write aggregates write volume per inode IN-KERNEL — the hot write path
// is never streamed (mirrors the `seen` syscall map). The path is resolved
// separately at open time (write_paths), because bpf_d_path is not allowlisted
// from vfs_write. Covers vfs_write (read/pwrite/write); vfs_writev and mmap
// writes are a documented v1 blind spot.
SEC("fentry/vfs_write")
int BPF_PROG(handle_write, struct file *file, const char *buf, size_t count)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	if (!ino)
		return 0;
	struct write_stat *st = bpf_map_lookup_elem(&write_stats, &ino);
	if (st) {
		st->count += 1;
		st->bytes += count;
		// Sample the first write large enough to fill the buffer (fixed size →
		// verifier-friendly; short writes are skipped, not partially read).
		if (st->sample_len == 0 && count >= WRITE_SAMPLE_LEN) {
			if (bpf_probe_read_user(st->sample, WRITE_SAMPLE_LEN, buf) == 0)
				st->sample_len = WRITE_SAMPLE_LEN;
		}
	} else {
		struct write_stat init = {};
		init.count = 1;
		init.bytes = count;
		if (count >= WRITE_SAMPLE_LEN) {
			if (bpf_probe_read_user(init.sample, WRITE_SAMPLE_LEN, buf) == 0)
				init.sample_len = WRITE_SAMPLE_LEN;
		}
		bpf_map_update_elem(&write_stats, &ino, &init, BPF_ANY);
	}
	return 0;
}

// handle_rename / handle_unlink stream the victim's NAME (basename via the
// dentry; a full path needs a struct path the LSM inode hooks don't provide).
// The detector sums rename+unlink run-level, so basename-granularity attribution
// is sufficient — these counts need not join the write nodes by full path.
SEC("fentry/security_inode_rename")
int BPF_PROG(handle_rename, struct inode *old_dir, struct dentry *old_dentry)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_RENAME;
	e->pid = tgid;
	e->ppid = 0;
	e->flags = 0;
	e->path[0] = 0;
	const unsigned char *name = BPF_CORE_READ(old_dentry, d_name.name);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_inode_unlink")
int BPF_PROG(handle_unlink, struct inode *dir, struct dentry *dentry)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_UNLINK;
	e->pid = tgid;
	e->ppid = 0;
	e->flags = 0;
	e->path[0] = 0;
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// handle_cap records which capabilities a tracked process is checked against
// (cap_capable is in commoncap, always in the LSM stack, so it fires regardless
// of which LSMs are active). This is "capabilities the program's actions
// required" — the evidence for a least-privilege caps.keep policy.
// Signature: cap_capable(const struct cred *cred, struct user_namespace *ns,
//                        int cap, unsigned int opts).
SEC("fentry/cap_capable")
int BPF_PROG(handle_cap, const struct cred *cred, struct user_namespace *ns, int cap)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	__u64 key = ((__u64)tgid << 32) | (__u32)cap;
	__u8 one = 1;
	bpf_map_update_elem(&seen_caps, &key, &one, BPF_ANY);
	return 0;
}

// handle_unshare records which namespace types a tracked process creates via
// unshare(2). The flags carry the CLONE_NEW* bits; userspace expands them into
// one JOINED_NS edge per type. (setns/clone-with-CLONE_NEW are deferred — most
// programs that create namespaces use unshare.) Semantics: "used a namespace of
// type X", not "joined instance Y" (we record no namespace inode).
SEC("fentry/ksys_unshare")
int BPF_PROG(handle_unshare, unsigned long unshare_flags)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	__u32 nsbits = (__u32)unshare_flags & CLONE_NEW_ALL;
	if (!nsbits)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_NS;
	e->pid = tgid;
	e->ppid = 0;
	e->flags = nsbits;
	e->path[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
