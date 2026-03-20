//go:build ignore

#include <linux/bpf.h>
#include <linux/sched.h>
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

enum {
	MAX_VAR_ARGS = 6,
	MAX_VAR_PAYLOAD = 512,
	MAX_EXECVE_ARGV = 8,
	MAX_EXECVE_ARG_STR = 128,
	MAX_EXECVE_STATE_VARS = 2,
	MAX_EXECVE_STATE_PAYLOAD = 256,
};

enum var_arg_kind {
	VAR_ARG_NONE = 0,
	VAR_ARG_STRING = 1,
	VAR_ARG_BYTES = 2,
	VAR_ARG_ARGV = 3,
};

enum var_arg_flags {
	VAR_FLAG_NONE = 0,
	VAR_FLAG_TRUNCATED = 1 << 0,
	VAR_FLAG_READ_ERROR = 1 << 1,
	VAR_FLAG_NULL_POINTER = 1 << 2,
};

struct var_arg_desc {
	__u8 arg_index;
	__u8 flags;
	__u16 offset;
	__u16 length;
	__u16 reserved;
};

struct event {
	__u64 ts;
	long syscall_id;
	long ret;
	__u64 args[6];
	struct var_arg_desc var_desc[MAX_VAR_ARGS];
	__u8 payload[MAX_VAR_PAYLOAD];
	__u32 pid;
	__u32 tid;
	__u32 seq;
	__u16 payload_len;
	__u8 arg_count;
	__u8 var_count;
	__u8 arg_types[6];
	__u8 var_reserved;
};

struct execve_snapshot {
	struct var_arg_desc var_desc[MAX_EXECVE_STATE_VARS];
	__u8 payload[MAX_EXECVE_STATE_PAYLOAD];
	__u16 payload_len;
	__u8 var_count;
	__u8 reserved;
};

struct syscall_data {
	__u64 ts;
	long syscall_id;
	unsigned long args[6];
	__u32 seq;
	__u8 selected;
	__u8 reserved[3];
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
	{
	 .syscall_id = __NR_write,
	 .arg_count = 3,
	 .arg_types = {ARG_FD, VAR_ARG_BYTES, ARG_UINT, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_read,
	 .arg_count = 3,
	 .arg_types = {ARG_FD, VAR_ARG_BYTES, ARG_UINT, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_execve,
	 .arg_count = 3,
	 .arg_types =
	 {VAR_ARG_STRING, VAR_ARG_ARGV, ARG_PTR, ARG_NONE, ARG_NONE,
	  ARG_NONE},
	 },
	{
	 .syscall_id = __NR_umask,
	 .arg_count = 1,
	 .arg_types = {ARG_MODE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
};

#define SYSCALL_SCHEMA_COUNT \
    (sizeof(scalar_syscall_schemas) / sizeof(scalar_syscall_schemas[0]))

volatile const __u8 follow_forks = 0;
volatile const __u8 trace_filter_enabled = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, __u8);
} trace_syscall_filter SEC(".maps");

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
	__type(value, struct execve_snapshot);
} execve_snapshots SEC(".maps");

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

struct clone3_args {
	__u64 flags;
};

static __always_inline __u8 is_process_clone(struct syscall_data *state)
{
	if (state->syscall_id == __NR_fork || state->syscall_id == __NR_vfork)
		return 1;

	if (state->syscall_id == __NR_clone) {
		if ((__u64) state->args[0] & CLONE_THREAD)
			return 0;
		return 1;
	}
	if (state->syscall_id == __NR_clone3) {
		struct clone3_args args = { 0 };

		if (bpf_probe_read_user(&args, sizeof(args),
					(const void *)state->args[0]) < 0)
			return 1;
		if (args.flags & CLONE_THREAD)
			return 0;
		return 1;
	}

	return 0;
}

static __always_inline __u8 should_track_unselected_syscall(long syscall_id)
{
	struct syscall_data state = { 0 };

	state.syscall_id = syscall_id;
	if (!follow_forks)
		return 0;

	return is_process_clone(&state);
}

static __always_inline void track_child_process(struct syscall_data *state,
						long ret)
{
	__u32 child_tgid;
	__u8 traced = 1;

	if (ret <= 0)
		return;
	if (!is_process_clone(state))
		return;
	if (!follow_forks)
		return;

	child_tgid = (__u32) ret;
	bpf_map_update_elem(&target_pids, &child_tgid, &traced, BPF_ANY);
}

static __always_inline void cleanup_tid_state(__u32 tid)
{
	bpf_map_delete_elem(&inflight_syscalls, &tid);
	bpf_map_delete_elem(&execve_snapshots, &tid);
	bpf_map_delete_elem(&tid_sequences, &tid);
}

static __always_inline void set_syscall_arg_schema(long syscall_id,
						   struct event *e)
{
	int i;
	int j;

#pragma unroll
	for (j = 0; j < SYSCALL_SCHEMA_COUNT; j++) {
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

static __always_inline void append_var_string(struct event *e,
					      __u8 arg_index, const char *ptr)
{
	__u32 available;
	int copied;
	struct var_arg_desc *desc;

	if (e->var_count >= MAX_VAR_ARGS)
		return;

	desc = &e->var_desc[e->var_count];
	desc->arg_index = arg_index;
	desc->flags = VAR_FLAG_NONE;
	desc->offset = 0;
	desc->length = 0;
	desc->reserved = 0;

	if (!ptr) {
		desc->flags |= VAR_FLAG_NULL_POINTER;
		e->var_count++;
		return;
	}

	if (e->payload_len > 0) {
		desc->flags |= VAR_FLAG_TRUNCATED;
		e->var_count++;
		return;
	}

	available = MAX_VAR_PAYLOAD;
	copied = bpf_probe_read_user_str(&e->payload[0], available, ptr);
	if (copied < 0) {
		desc->flags |= VAR_FLAG_READ_ERROR;
		e->var_count++;
		return;
	}

	if ((__u32) copied == available)
		desc->flags |= VAR_FLAG_TRUNCATED;

	if (copied > 0)
		desc->length = copied - 1;
	e->payload_len = desc->length;
	e->var_count++;
}

static __always_inline void append_var_bytes(struct event *e,
					     __u8 arg_index,
					     const void *ptr, __u64 size)
{
	__u32 available;
	__u32 to_copy;
	struct var_arg_desc *desc;

	if (e->var_count >= MAX_VAR_ARGS)
		return;

	desc = &e->var_desc[e->var_count];
	desc->arg_index = arg_index;
	desc->flags = VAR_FLAG_NONE;
	desc->offset = 0;
	desc->length = 0;
	desc->reserved = 0;

	if (!ptr) {
		desc->flags |= VAR_FLAG_NULL_POINTER;
		e->var_count++;
		return;
	}

	if (e->payload_len > 0) {
		desc->flags |= VAR_FLAG_TRUNCATED;
		e->var_count++;
		return;
	}

	available = MAX_VAR_PAYLOAD;
	to_copy = available;
	if ((__u64) to_copy > size) {
		to_copy = size;
	} else if (size > (__u64) to_copy) {
		desc->flags |= VAR_FLAG_TRUNCATED;
	}

	if (to_copy == 0) {
		e->var_count++;
		return;
	}

	if (bpf_probe_read_user(&e->payload[0], to_copy, ptr) < 0) {
		desc->flags |= VAR_FLAG_READ_ERROR;
		e->var_count++;
		return;
	}

	desc->length = to_copy;
	e->payload_len = to_copy;
	e->var_count++;
}

static __always_inline void append_var_argv(struct event *e,
					    __u8 arg_index,
					    const char *const *argv)
{
	__u32 start;
	__u32 cursor;
	__u8 exhausted_argv_slots = 1;
	int i;
	struct var_arg_desc *desc;

	if (e->var_count >= MAX_VAR_ARGS)
		return;

	desc = &e->var_desc[e->var_count];
	desc->arg_index = arg_index;
	desc->flags = VAR_FLAG_NONE;
	desc->offset = e->payload_len;
	desc->length = 0;
	desc->reserved = 0;

	if (!argv) {
		desc->flags |= VAR_FLAG_NULL_POINTER;
		e->var_count++;
		return;
	}

	start = e->payload_len;
	if (start >= MAX_VAR_PAYLOAD) {
		desc->flags |= VAR_FLAG_TRUNCATED;
		e->var_count++;
		return;
	}

	cursor = start;

#pragma unroll
	for (i = 0; i < MAX_EXECVE_ARGV; i++) {
		const char *arg_ptr = 0;
		int copied;

		if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) <
		    0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
			exhausted_argv_slots = 0;
			break;
		}

		if (!arg_ptr) {
			exhausted_argv_slots = 0;
			break;
		}

		if (cursor > MAX_VAR_PAYLOAD - MAX_EXECVE_ARG_STR) {
			desc->flags |= VAR_FLAG_TRUNCATED;
			exhausted_argv_slots = 0;
			break;
		}

		copied =
		    bpf_probe_read_user_str(&e->payload[cursor],
					    MAX_EXECVE_ARG_STR, arg_ptr);
		if (copied < 0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
			exhausted_argv_slots = 0;
			break;
		}

		if (copied > MAX_EXECVE_ARG_STR)
			copied = MAX_EXECVE_ARG_STR;

		cursor += copied;
		if (copied == MAX_EXECVE_ARG_STR) {
			desc->flags |= VAR_FLAG_TRUNCATED;
			exhausted_argv_slots = 0;
			break;
		}
	}

	if (exhausted_argv_slots) {
		const char *next_ptr = 0;

		if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr),
					&argv[MAX_EXECVE_ARGV]) < 0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
		} else if (next_ptr) {
			desc->flags |= VAR_FLAG_TRUNCATED;
		}
	}

	if (cursor > start) {
		desc->length = cursor - start;
		e->payload_len = cursor;
	}
	e->var_count++;
}

static __always_inline void append_execve_var_string(struct execve_snapshot
						     *snap, __u8 arg_index,
						     const char *ptr)
{
	int copied;
	struct var_arg_desc *desc;

	if (snap->var_count >= MAX_EXECVE_STATE_VARS)
		return;

	desc = &snap->var_desc[snap->var_count];
	desc->arg_index = arg_index;
	desc->flags = VAR_FLAG_NONE;
	desc->offset = 0;
	desc->length = 0;
	desc->reserved = 0;

	if (!ptr) {
		desc->flags |= VAR_FLAG_NULL_POINTER;
		snap->var_count++;
		return;
	}

	copied =
	    bpf_probe_read_user_str(&snap->payload[0], MAX_EXECVE_ARG_STR, ptr);
	if (copied < 0) {
		desc->flags |= VAR_FLAG_READ_ERROR;
		snap->var_count++;
		return;
	}

	if (copied > MAX_EXECVE_ARG_STR)
		copied = MAX_EXECVE_ARG_STR;

	if (copied == MAX_EXECVE_ARG_STR)
		desc->flags |= VAR_FLAG_TRUNCATED;

	if (copied > 0) {
		desc->length = copied - 1;
		snap->payload_len = desc->length;
	}
	snap->var_count++;
}

static __always_inline void append_execve_var_argv(struct execve_snapshot *snap,
						   __u8 arg_index,
						   const char *const *argv)
{
	__u32 start;
	__u32 cursor;
	__u8 exhausted_argv_slots = 1;
	int i;
	struct var_arg_desc *desc;

	if (snap->var_count >= MAX_EXECVE_STATE_VARS)
		return;

	desc = &snap->var_desc[snap->var_count];
	desc->arg_index = arg_index;
	desc->flags = VAR_FLAG_NONE;
	desc->offset = snap->payload_len;
	desc->length = 0;
	desc->reserved = 0;

	if (!argv) {
		desc->flags |= VAR_FLAG_NULL_POINTER;
		snap->var_count++;
		return;
	}

	start = snap->payload_len;
	if (start >= MAX_EXECVE_STATE_PAYLOAD) {
		desc->flags |= VAR_FLAG_TRUNCATED;
		snap->var_count++;
		return;
	}

	cursor = start;

#pragma unroll
	for (i = 0; i < MAX_EXECVE_ARGV; i++) {
		const char *arg_ptr = 0;
		int copied;

		if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) <
		    0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
			exhausted_argv_slots = 0;
			break;
		}

		if (!arg_ptr) {
			exhausted_argv_slots = 0;
			break;
		}

		if (cursor > MAX_EXECVE_STATE_PAYLOAD - MAX_EXECVE_ARG_STR) {
			desc->flags |= VAR_FLAG_TRUNCATED;
			exhausted_argv_slots = 0;
			break;
		}

		copied = bpf_probe_read_user_str(&snap->payload[cursor],
						 MAX_EXECVE_ARG_STR, arg_ptr);
		if (copied < 0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
			exhausted_argv_slots = 0;
			break;
		}

		if (copied > MAX_EXECVE_ARG_STR)
			copied = MAX_EXECVE_ARG_STR;

		cursor += copied;
		if (copied == MAX_EXECVE_ARG_STR) {
			desc->flags |= VAR_FLAG_TRUNCATED;
			exhausted_argv_slots = 0;
			break;
		}
	}

	if (exhausted_argv_slots) {
		const char *next_ptr = 0;

		if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr),
					&argv[MAX_EXECVE_ARGV]) < 0) {
			desc->flags |= VAR_FLAG_READ_ERROR;
		} else if (next_ptr) {
			desc->flags |= VAR_FLAG_TRUNCATED;
		}
	}

	if (cursor > start) {
		desc->length = cursor - start;
		snap->payload_len = cursor;
	}
	snap->var_count++;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 tid = (__u32) pid_tgid;
	__u32 syscall_id = (__u32) ctx->id;
	__u32 next_seq = 1;
	__u32 *prev_seq;
	__u8 *selected_syscall;
	__u8 selected = 1;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	if (trace_filter_enabled) {
		selected_syscall =
		    bpf_map_lookup_elem(&trace_syscall_filter, &syscall_id);
		if (!selected_syscall) {
			selected = 0;
			if (!should_track_unselected_syscall(ctx->id))
				return 0;
		}
	}

	prev_seq = bpf_map_lookup_elem(&tid_sequences, &tid);
	if (prev_seq)
		next_seq = *prev_seq + 1;
	bpf_map_update_elem(&tid_sequences, &tid, &next_seq, BPF_ANY);

	struct syscall_data state;

	__builtin_memset(&state, 0, sizeof(state));
	state.ts = bpf_ktime_get_ns();
	state.syscall_id = ctx->id;
	state.seq = next_seq;
	state.selected = selected;

	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	state.args[4] = ctx->args[4];
	state.args[5] = ctx->args[5];

	if (ctx->id == __NR_execve) {
		struct execve_snapshot zero = { 0 };
		struct execve_snapshot *snapshot;

		bpf_map_update_elem(&execve_snapshots, &tid, &zero, BPF_ANY);
		snapshot = bpf_map_lookup_elem(&execve_snapshots, &tid);
		if (snapshot) {
			append_execve_var_string(snapshot, 0,
						 (const char *)ctx->args[0]);
			append_execve_var_argv(snapshot, 1,
					       (const char *const *)
					       ctx->args[1]);
		}
	}

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
	int j;
	int k;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	struct syscall_data *state =
	    bpf_map_lookup_elem(&inflight_syscalls, &tid);
	if (!state)
		return 0;

	track_child_process(state, ctx->ret);
	if (!state->selected) {
		bpf_map_delete_elem(&inflight_syscalls, &tid);
		return 0;
	}

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
	e->payload_len = 0;
	e->var_count = 0;
	e->var_reserved = 0;

#pragma unroll
	for (i = 0; i < 6; i++) {
		e->args[i] = state->args[i];
		e->arg_types[i] = ARG_NONE;
		e->var_desc[i].arg_index = 0;
		e->var_desc[i].flags = 0;
		e->var_desc[i].offset = 0;
		e->var_desc[i].length = 0;
		e->var_desc[i].reserved = 0;
	}

#pragma unroll
	for (j = 0; j < MAX_VAR_PAYLOAD; j++)
		e->payload[j] = 0;

	set_syscall_arg_schema(state->syscall_id, e);
	if (state->syscall_id == __NR_open) {
		append_var_string(e, 0, (const char *)state->args[0]);
		e->arg_types[0] = VAR_ARG_STRING;
	}

	if (state->syscall_id == __NR_openat) {
		append_var_string(e, 1, (const char *)state->args[1]);
		e->arg_types[1] = VAR_ARG_STRING;
	}

	if (state->syscall_id == __NR_execve) {
		struct execve_snapshot *snapshot =
		    bpf_map_lookup_elem(&execve_snapshots, &tid);

		if (snapshot) {
			e->payload_len = snapshot->payload_len;
			e->var_count = snapshot->var_count;

#pragma unroll
			for (k = 0; k < MAX_EXECVE_STATE_VARS; k++)
				e->var_desc[k] = snapshot->var_desc[k];

#pragma unroll
			for (k = 0; k < MAX_EXECVE_STATE_PAYLOAD; k++)
				e->payload[k] = snapshot->payload[k];
		} else {
			e->var_count = 2;
			e->var_desc[0].arg_index = 0;
			e->var_desc[0].flags = VAR_FLAG_READ_ERROR;
			e->var_desc[1].arg_index = 1;
			e->var_desc[1].flags = VAR_FLAG_READ_ERROR;
		}
		bpf_map_delete_elem(&execve_snapshots, &tid);
	}

	if (state->syscall_id == __NR_write) {
		append_var_bytes(e, 1, (const void *)state->args[1],
				 (__u64) state->args[2]);
	}

	if (state->syscall_id == __NR_read && ctx->ret > 0) {
		append_var_bytes(e, 1, (const void *)state->args[1],
				 (__u64) ctx->ret);
	}

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight_syscalls, &tid);

	if (state->syscall_id == __NR_exit
	    || state->syscall_id == __NR_exit_group) {
		cleanup_tid_state(tid);
		if (state->syscall_id == __NR_exit_group)
			bpf_map_delete_elem(&target_pids, &tgid);
	}

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 tid = (__u32) pid_tgid;

	(void)ctx;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	cleanup_tid_state(tid);
	if (tid == tgid)
		bpf_map_delete_elem(&target_pids, &tgid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
