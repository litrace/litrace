//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
	__u64 ts;
	__u32 pid;
	__u32 tid;
	long syscall_id;
	long ret;
};

struct inflight {
	__u64 ts;
	long syscall_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct inflight);
} inflight_syscalls SEC(".maps");

struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 tid = (__u32) pid_tgid;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	struct inflight state = {
		.ts = bpf_ktime_get_ns(),
		.syscall_id = ctx->id,
	};

	bpf_map_update_elem(&inflight_syscalls, &tid, &state, BPF_ANY);
	return 0;
}

struct sys_exit_args {
	__u64 pad;
	long id;
	long ret;
};

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 tid = (__u32) pid_tgid;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	struct inflight *state = bpf_map_lookup_elem(&inflight_syscalls, &tid);
	if (!state)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts = state->ts;
	e->pid = tgid;
	e->tid = tid;
	e->syscall_id = state->syscall_id;
	e->ret = ctx->ret;

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight_syscalls, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
