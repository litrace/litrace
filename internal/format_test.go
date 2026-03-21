package trace

import (
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestSimpleArgsDecode(t *testing.T) {
	tests := []struct {
		name string
		ev   event
		want string
	}{
		{
			name: "close fd",
			ev: event{
				SyscallID: int64(unix.SYS_CLOSE),
				Ret:       0,
				ArgCount:  1,
				Args:      [6]uint64{42},
				ArgTypes:  [6]uint8{argFD},
			},
			want: "close(42) = 0",
		},
		{
			name: "getpid has no arguments",
			ev: event{
				SyscallID: int64(unix.SYS_GETPID),
				Ret:       1234,
				ArgCount:  0,
			},
			want: "getpid() = 1234",
		},
		{
			name: "lseek with symbolic whence",
			ev: event{
				SyscallID: int64(unix.SYS_LSEEK),
				Ret:       128,
				ArgCount:  3,
				Args:      [6]uint64{3, 128, uint64(unix.SEEK_SET)},
				ArgTypes:  [6]uint8{argFD, argOff, argInt},
			},
			want: "lseek(3, 128, SEEK_SET) = 128",
		},
		{
			name: "clock_gettime with int and pointer args",
			ev: event{
				SyscallID: int64(unix.SYS_CLOCK_GETTIME),
				Ret:       0,
				ArgCount:  2,
				Args:      [6]uint64{uint64(unix.CLOCK_REALTIME), 0x7ffc1234},
				ArgTypes:  [6]uint8{argInt, argPtr},
			},
			want: "clock_gettime(0, 0x7ffc1234) = 0",
		},
		{
			name: "eventfd with unsigned arg",
			ev: event{
				SyscallID: int64(unix.SYS_EVENTFD),
				Ret:       3,
				ArgCount:  1,
				Args:      [6]uint64{7},
				ArgTypes:  [6]uint8{argUint},
			},
			want: "eventfd(7) = 3",
		},
		{
			name: "fchmod mode octal",
			ev: event{
				SyscallID: int64(unix.SYS_FCHMOD),
				Ret:       0,
				ArgCount:  2,
				Args:      [6]uint64{7, 0755},
				ArgTypes:  [6]uint8{argFD, argMode},
			},
			want: "fchmod(7, 0755) = 0",
		},
		{
			name: "umask mode argument and return octal",
			ev: event{
				SyscallID: int64(unix.SYS_UMASK),
				Ret:       0022,
				ArgCount:  1,
				Args:      [6]uint64{0006},
				ArgTypes:  [6]uint8{argMode},
			},
			want: "umask(006) = 022",
		},
		{
			name: "umask error return keeps errno formatting",
			ev: event{
				SyscallID: int64(unix.SYS_UMASK),
				Ret:       -int64(unix.EPERM),
				ArgCount:  1,
				Args:      [6]uint64{0006},
				ArgTypes:  [6]uint8{argMode},
			},
			want: "umask(006) = -1 EPERM (operation not permitted)",
		},
		{
			name: "raw fallback for unknown syscall schema",
			ev: event{
				SyscallID: 9999,
				Ret:       -int64(unix.EPERM),
				ArgCount:  2,
				Args:      [6]uint64{0x12, 0x34},
				ArgTypes:  [6]uint8{argRaw, argRaw},
			},
			want: "syscall_0x270f(0x12, 0x34) = -1 EPERM (operation not permitted)",
		},
		{
			name: "openat with variable path string",
			ev: event{
				SyscallID: int64(unix.SYS_OPENAT),
				Ret:       3,
				ArgCount:  4,
				Args:      [6]uint64{uint64(^uint32(99)), 0, 0, 0},
				ArgTypes:  [6]uint8{argFD, varArgString, argFlags, argMode},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   17,
				}},
				PayloadLen: 17,
				Payload:    [512]byte{'/', 't', 'm', 'p', '/', 'l', 'i', 't', 'r', 'a', 'c', 'e', '_', 't', 'e', 's', 't'},
			},
			want: "openat(AT_FDCWD, \"/tmp/litrace_test\", O_RDONLY) = 3",
		},
		{
			name: "openat with create flag includes mode",
			ev: event{
				SyscallID: int64(unix.SYS_OPENAT),
				Ret:       3,
				ArgCount:  4,
				Args:      [6]uint64{uint64(^uint32(99)), 0, uint64(unix.O_CREAT), 0600},
				ArgTypes:  [6]uint8{argFD, varArgString, argFlags, argMode},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   17,
				}},
				PayloadLen: 17,
				Payload:    [512]byte{'/', 't', 'm', 'p', '/', 'l', 'i', 't', 'r', 'a', 'c', 'e', '_', 't', 'e', 's', 't'},
			},
			want: "openat(AT_FDCWD, \"/tmp/litrace_test\", O_RDONLY|O_CREAT, 0600) = 3",
		},
		{
			name: "openat with symbolic flags preserves unknown bits",
			ev: event{
				SyscallID: int64(unix.SYS_OPENAT),
				Ret:       3,
				ArgCount:  4,
				Args:      [6]uint64{9, 0, uint64(unix.O_WRONLY | unix.O_CLOEXEC | 0x80000000), 0},
				ArgTypes:  [6]uint8{argFD, varArgString, argFlags, argMode},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   17,
				}},
				PayloadLen: 17,
				Payload:    [512]byte{'/', 't', 'm', 'p', '/', 'l', 'i', 't', 'r', 'a', 'c', 'e', '_', 't', 'e', 's', 't'},
			},
			want: "openat(9, \"/tmp/litrace_test\", O_WRONLY|O_CLOEXEC|0x80000000) = 3",
		},
		{
			name: "open path with truncation marker",
			ev: event{
				SyscallID: int64(unix.SYS_OPEN),
				Ret:       4,
				ArgCount:  3,
				Args:      [6]uint64{0, 0, 0},
				ArgTypes:  [6]uint8{varArgString, argFlags, argMode},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 0,
					Offset:   0,
					Length:   5,
					Flags:    varFlagTruncated,
				}},
				PayloadLen: 5,
				Payload:    [512]byte{'/', 'v', 'a', 'r', '/'},
			},
			want: "open(\"/var/\"..., O_RDONLY) = 4",
		},
		{
			name: "write with variable bytes preview",
			ev: event{
				SyscallID: int64(unix.SYS_WRITE),
				Ret:       6,
				ArgCount:  3,
				Args:      [6]uint64{1, 0, 6},
				ArgTypes:  [6]uint8{argFD, varArgBytes, argUint},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   6,
				}},
				PayloadLen: 6,
				Payload:    [512]byte{'h', 'e', 'l', 'l', 'o', '\n'},
			},
			want: "write(1, \"hello\\n\", 6) = 6",
		},
		{
			name: "write bytes truncation marker",
			ev: event{
				SyscallID: int64(unix.SYS_WRITE),
				Ret:       10,
				ArgCount:  3,
				Args:      [6]uint64{2, 0, 10},
				ArgTypes:  [6]uint8{argFD, varArgBytes, argUint},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   4,
					Flags:    varFlagTruncated,
				}},
				PayloadLen: 4,
				Payload:    [512]byte{'D', 'A', 'T', 'A'},
			},
			want: "write(2, \"DATA\"..., 10) = 10",
		},
		{
			name: "read with variable bytes preview uses return length",
			ev: event{
				SyscallID: int64(unix.SYS_READ),
				Ret:       3,
				ArgCount:  3,
				Args:      [6]uint64{4, 0, 10},
				ArgTypes:  [6]uint8{argFD, varArgBytes, argUint},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   3,
				}},
				PayloadLen: 3,
				Payload:    [512]byte{'a', 'b', 'c'},
			},
			want: "read(4, \"abc\", 10) = 3",
		},
		{
			name: "read with zero-length payload renders empty string",
			ev: event{
				SyscallID: int64(unix.SYS_READ),
				Ret:       0,
				ArgCount:  3,
				Args:      [6]uint64{4, 0, 10},
				ArgTypes:  [6]uint8{argFD, varArgBytes, argUint},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   0,
				}},
				PayloadLen: 0,
			},
			want: "read(4, \"\", 10) = 0",
		},
		{
			name: "fstat with decoded stat buffer",
			ev: func() event {
				payload := encodeStatPayload(t, unix.Stat_t{
					Mode: unix.S_IFREG | 0644,
					Size: 131471,
				})
				ev := event{
					SyscallID:  int64(unix.SYS_FSTAT),
					Ret:        0,
					ArgCount:   2,
					Args:       [6]uint64{3, 0x7ffd47b78430},
					ArgTypes:   [6]uint8{argFD, varArgBytes},
					VarCount:   1,
					PayloadLen: uint16(len(payload)),
				}
				ev.VarDesc[0] = varArgDesc{
					ArgIndex: 1,
					Offset:   0,
					Length:   uint16(len(payload)),
				}
				copy(ev.Payload[:], payload)
				return ev
			}(),
			want: "fstat(3, {st_mode=S_IFREG|0644, st_size=131471, ...}) = 0",
		},
		{
			name: "fstat error keeps pointer formatting",
			ev: event{
				SyscallID: int64(unix.SYS_FSTAT),
				Ret:       -int64(unix.EBADF),
				ArgCount:  2,
				Args:      [6]uint64{3, 0x7ffd47b78430},
				ArgTypes:  [6]uint8{argFD, argPtr},
			},
			want: "fstat(3, 0x7ffd47b78430) = -1 EBADF (bad file descriptor)",
		},
		{
			name: "fstat truncated stat buffer falls back to placeholder",
			ev: event{
				SyscallID: int64(unix.SYS_FSTAT),
				Ret:       0,
				ArgCount:  2,
				Args:      [6]uint64{3, 0x7ffd47b78430},
				ArgTypes:  [6]uint8{argFD, varArgBytes},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   8,
				}},
				PayloadLen: 8,
				Payload:    [512]byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			want: "fstat(3, <?>) = 0",
		},
		{
			name: "execve with filename and argv summary",
			ev: event{
				SyscallID: int64(unix.SYS_EXECVE),
				Ret:       0,
				ArgCount:  3,
				Args:      [6]uint64{0, 0, 0x7ffc1234},
				ArgTypes:  [6]uint8{varArgString, varArgArgv, argPtr},
				VarCount:  2,
				VarDesc: [6]varArgDesc{
					{
						ArgIndex: 0,
						Offset:   0,
						Length:   11,
					},
					{
						ArgIndex: 1,
						Offset:   11,
						Length:   15,
					},
				},
				PayloadLen: 26,
				Payload: [512]byte{
					'/', 'b', 'i', 'n', '/', 'e', 'c', 'h', 'o', ' ', 'x',
					'e', 'c', 'h', 'o', 0, 'h', 'e', 'l', 'l', 'o', 0, '-', 'n', 0, 0,
				},
			},
			want: "execve(\"/bin/echo x\", [\"echo\", \"hello\", \"-n\", \"\"], 0x7ffc1234) = 0",
		},
		{
			name: "execve argv truncation marker",
			ev: event{
				SyscallID: int64(unix.SYS_EXECVE),
				Ret:       -int64(unix.E2BIG),
				ArgCount:  3,
				Args:      [6]uint64{0, 0, 0x7ffc55aa},
				ArgTypes:  [6]uint8{varArgString, varArgArgv, argPtr},
				VarCount:  2,
				VarDesc: [6]varArgDesc{
					{
						ArgIndex: 0,
						Offset:   0,
						Length:   9,
					},
					{
						ArgIndex: 1,
						Offset:   9,
						Length:   10,
						Flags:    varFlagTruncated,
					},
				},
				PayloadLen: 19,
				Payload: [512]byte{
					'/', 'b', 'i', 'n', '/', 's', 'h', ' ', 'x',
					's', 'h', 0, '-', 'c', 0, 'e', 'c', 'h', 'o',
				},
			},
			want: "execve(\"/bin/sh x\", [\"sh\", \"-c\", \"echo\"]..., 0x7ffc55aa) = -1 E2BIG (argument list too long)",
		},
		{
			name: "execve argv read error with null filename",
			ev: event{
				SyscallID: int64(unix.SYS_EXECVE),
				Ret:       -int64(unix.EFAULT),
				ArgCount:  3,
				Args:      [6]uint64{0, 0, 0x0},
				ArgTypes:  [6]uint8{varArgString, varArgArgv, argPtr},
				VarCount:  2,
				VarDesc: [6]varArgDesc{
					{
						ArgIndex: 0,
						Flags:    varFlagNullPointer,
					},
					{
						ArgIndex: 1,
						Flags:    varFlagReadError,
					},
				},
			},
			want: "execve(NULL, [<?>], 0x0) = -1 EFAULT (bad address)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatEventLine(tt.ev)
			if got != tt.want {
				t.Fatalf("formatEventLine() mismatch for %s: got %q want %q", tt.name, got, tt.want)
			}
		})
	}
}

func encodeStatPayload(t *testing.T, st unix.Stat_t) []byte {
	t.Helper()

	size := int(unsafe.Sizeof(st))
	buf := make([]byte, size)
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&st)), size))
	return buf
}

func TestFormatSummary(t *testing.T) {
	summary := map[int64]*syscallSummary{
		int64(unix.SYS_OPENAT): {Calls: 2, Errors: 1, TotalNs: 3000},
		int64(unix.SYS_CLOSE):  {Calls: 1, Errors: 0, TotalNs: 1000},
	}

	got := FormatSummary(summary)
	wantLines := []string{
		"% time     seconds  usecs/call     calls    errors syscall",
		"------ ----------- ----------- --------- --------- ----------------",
		" 75.00    0.000003           1         2         1 openat",
		" 25.00    0.000001           1         1         0 close",
		"100.00    0.000004           1         3         1 total",
	}

	for _, line := range wantLines {
		if !strings.Contains(got, line) {
			t.Fatalf("FormatSummary() missing line %q in output:\n%s", line, got)
		}
	}
}

func TestFormatEventPrefix(t *testing.T) {
	const rootTGID = uint32(4242)

	tests := []struct {
		name string
		ev   event
		want string
	}{
		{
			name: "root process has no prefix",
			ev: event{
				Pid: rootTGID,
				Tid: rootTGID,
			},
			want: "",
		},
		{
			name: "child process is prefixed",
			ev: event{
				Pid: 9001,
				Tid: 9001,
			},
			want: "[pid 9001] ",
		},
		{
			name: "thread in root process is prefixed",
			ev: event{
				Pid: rootTGID,
				Tid: 9002,
			},
			want: "[pid 9002] ",
		},
		{
			name: "zero tid emits no prefix",
			ev:   event{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatEventPrefix(tt.ev, rootTGID)
			if got != tt.want {
				t.Fatalf("formatEventPrefix() mismatch for %s: got %q want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestFormatOutputLine(t *testing.T) {
	const rootTGID = uint32(4242)

	tests := []struct {
		name string
		ev   event
		want string
	}{
		{
			name: "root process line has no pid prefix",
			ev: event{
				Pid:       rootTGID,
				Tid:       rootTGID,
				SyscallID: int64(unix.SYS_CLOSE),
				Ret:       0,
				ArgCount:  1,
				Args:      [6]uint64{11},
				ArgTypes:  [6]uint8{argFD},
			},
			want: "close(11) = 0",
		},
		{
			name: "child process line carries strace style pid prefix",
			ev: event{
				Pid:       9001,
				Tid:       9001,
				SyscallID: int64(unix.SYS_CLOSE),
				Ret:       0,
				ArgCount:  1,
				Args:      [6]uint64{12},
				ArgTypes:  [6]uint8{argFD},
			},
			want: "[pid 9001] close(12) = 0",
		},
		{
			name: "thread line uses task id in pid prefix",
			ev: event{
				Pid:       rootTGID,
				Tid:       9002,
				SyscallID: int64(unix.SYS_CLOSE),
				Ret:       0,
				ArgCount:  1,
				Args:      [6]uint64{13},
				ArgTypes:  [6]uint8{argFD},
			},
			want: "[pid 9002] close(13) = 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatOutputLine(tt.ev, rootTGID)
			if got != tt.want {
				t.Fatalf("formatOutputLine() mismatch for %s: got %q want %q", tt.name, got, tt.want)
			}
		})
	}
}
