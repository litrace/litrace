//go:build ignore

#include <linux/bpf.h>
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>

enum arg_type {
	ARG_NONE = 0,
	ARG_INT = 1,
	ARG_UINT = 2,
	ARG_FD = 3,
	ARG_MODE = 4,
	ARG_FLAGS = 5,
	ARG_OFF = 6,
	ARG_PTR = 7,
	ARG_RAW = 255,
};

struct event {
	__u64 ts;
	long syscall_id;
	long ret;
	__u64 args[6];
	__u32 pid;
	__u32 tid;
	__u32 seq;
	__u8 arg_count;
	__u8 arg_types[6];
	__u8 reserved[5];
};

struct syscall_data {
	__u64 ts;
	long syscall_id;
	unsigned long args[6];
	__u32 seq;
};

struct syscall_arg_schema {
	long syscall_id;
	__u8 arg_count;
	__u8 arg_types[6];
};

static const struct syscall_arg_schema scalar_syscall_schemas[] = {
	{
	 .syscall_id = __NR_close,
	 .arg_count = 1,
	 .arg_types = {ARG_FD, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_lseek,
	 .arg_count = 3,
	 .arg_types = {ARG_FD, ARG_OFF, ARG_INT, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_fchmod,
	 .arg_count = 2,
	 .arg_types = {ARG_FD, ARG_MODE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
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
	__type(value, struct syscall_data);
} inflight_syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u32);
} tid_sequences SEC(".maps");

struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};

static __always_inline void set_syscall_arg_schema(long syscall_id,
						   struct event *e)
{
	int i;
	int j;

#pragma unroll
	for (j = 0; j < 3; j++) {
		const struct syscall_arg_schema *schema =
		    &scalar_syscall_schemas[j];

		if (schema->syscall_id != syscall_id)
			continue;

		e->arg_count = schema->arg_count;
#pragma unroll
		for (i = 0; i < 6; i++)
			e->arg_types[i] = schema->arg_types[i];
		return;
	}

	e->arg_count = 6;
#pragma unroll
	for (i = 0; i < 6; i++)
		e->arg_types[i] = ARG_RAW;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 tid = (__u32) pid_tgid;
	__u32 next_seq = 1;
	__u32 *prev_seq;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	prev_seq = bpf_map_lookup_elem(&tid_sequences, &tid);
	if (prev_seq)
		next_seq = *prev_seq + 1;
	bpf_map_update_elem(&tid_sequences, &tid, &next_seq, BPF_ANY);

	struct syscall_data state = {
		.ts = bpf_ktime_get_ns(),
		.syscall_id = ctx->id,
		.seq = next_seq,
	};

	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	state.args[4] = ctx->args[4];
	state.args[5] = ctx->args[5];

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
	int i;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	struct syscall_data *state =
	    bpf_map_lookup_elem(&inflight_syscalls, &tid);
	if (!state)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts = state->ts;
	e->pid = tgid;
	e->tid = tid;
	e->seq = state->seq;
	e->syscall_id = state->syscall_id;
	e->ret = ctx->ret;
	e->arg_count = 0;

#pragma unroll
	for (i = 0; i < 6; i++) {
		e->args[i] = state->args[i];
		e->arg_types[i] = ARG_NONE;
	}

	set_syscall_arg_schema(state->syscall_id, e);

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight_syscalls, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
