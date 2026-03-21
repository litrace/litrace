/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LITRACE_TYPES_H
#define LITRACE_TYPES_H

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
	GENERIC_VAR_SLOT_SIZE = MAX_VAR_PAYLOAD / 2,
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
	__u64 dur;
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

struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};

struct clone3_args {
	__u64 flags;
};

struct sys_exit_args {
	__u64 pad;
	long id;
	long ret;
};

#endif
