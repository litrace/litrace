//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (!bpf_map_lookup_elem(&target_pids, &tgid))
		return 0;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
