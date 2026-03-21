#ifndef LITRACE_SYSCALL_SCHEMA_H
#define LITRACE_SYSCALL_SCHEMA_H

static const struct syscall_arg_schema syscall_schemas[] = {
	{
	 .syscall_id = __NR_read,
	 .arg_count = 3,
	 .arg_types = {ARG_FD, VAR_ARG_BYTES, ARG_UINT, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_write,
	 .arg_count = 3,
	 .arg_types = {ARG_FD, VAR_ARG_BYTES, ARG_UINT, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_open,
	 .arg_count = 3,
	 .arg_types = {VAR_ARG_STRING, ARG_FLAGS, ARG_MODE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
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
	 .syscall_id = __NR_rt_sigreturn,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_sched_yield,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_pause,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getpid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_fork,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_vfork,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
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
	 .syscall_id = __NR_fchmod,
	 .arg_count = 2,
	 .arg_types = {ARG_FD, ARG_MODE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_umask,
	 .arg_count = 1,
	 .arg_types = {ARG_MODE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getuid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getgid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_geteuid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getegid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getppid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_getpgrp,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_setsid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_munlockall,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_vhangup,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_sync,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_gettid,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_restart_syscall,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_inotify_init,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_openat,
	 .arg_count = 4,
	 .arg_types = {ARG_FD, VAR_ARG_STRING, ARG_FLAGS, ARG_MODE, ARG_NONE,
		       ARG_NONE},
	 },
	{
	 .syscall_id = __NR_uretprobe,
	 .arg_count = 0,
	 .arg_types = {ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE,
		       ARG_NONE},
	 },
};

#endif
