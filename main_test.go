package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseCLIArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantFollow   bool
		wantProgName string
		wantProgPath string
		wantProgArgs []string
		wantErr      string
	}{
		{
			name:    "requires program",
			args:    []string{},
			wantErr: "usage: litrace [-f] <program> [args...]",
		},
		{
			name:    "rejects unknown option",
			args:    []string{"-x", "/bin/echo"},
			wantErr: "unknown option \"-x\"",
		},
		{
			name:         "supports -f before program",
			args:         []string{"-f", "/bin/echo", "hi"},
			wantFollow:   true,
			wantProgName: "/bin/echo",
			wantProgPath: "/bin/echo",
			wantProgArgs: []string{"hi"},
		},
		{
			name:         "supports -- to stop option parsing",
			args:         []string{"--", "/bin/echo", "ok"},
			wantProgName: "/bin/echo",
			wantProgPath: "/bin/echo",
			wantProgArgs: []string{"ok"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseCLIArgs("litrace", tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseCLIArgs() expected error %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseCLIArgs() error mismatch: got %q want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseCLIArgs() unexpected error: %v", err)
			}
			if cfg.followForks != tt.wantFollow {
				t.Fatalf("parseCLIArgs() followForks mismatch: got %v want %v", cfg.followForks, tt.wantFollow)
			}
			if cfg.programName != tt.wantProgName {
				t.Fatalf("parseCLIArgs() programName mismatch: got %q want %q", cfg.programName, tt.wantProgName)
			}
			if cfg.programPath != tt.wantProgPath {
				t.Fatalf("parseCLIArgs() programPath mismatch: got %q want %q", cfg.programPath, tt.wantProgPath)
			}
			if len(cfg.programArgs) != len(tt.wantProgArgs) {
				t.Fatalf("parseCLIArgs() programArgs length mismatch: got %d want %d", len(cfg.programArgs), len(tt.wantProgArgs))
			}
			for i := range cfg.programArgs {
				if cfg.programArgs[i] != tt.wantProgArgs[i] {
					t.Fatalf("parseCLIArgs() programArgs[%d] mismatch: got %q want %q", i, cfg.programArgs[i], tt.wantProgArgs[i])
				}
			}
		})
	}
}

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
				ArgCount:  3,
				Args:      [6]uint64{uint64(^uint32(99)), 0, 0},
				ArgTypes:  [6]uint8{argFD, varArgString, argFlags},
				VarCount:  1,
				VarDesc: [6]varArgDesc{{
					ArgIndex: 1,
					Offset:   0,
					Length:   17,
				}},
				PayloadLen: 17,
				Payload:    [512]byte{'/', 't', 'm', 'p', '/', 'l', 'i', 't', 'r', 'a', 'c', 'e', '_', 't', 'e', 's', 't'},
			},
			want: "openat(-100, \"/tmp/litrace_test\", 0x0) = 3",
		},
		{
			name: "open path with truncation marker",
			ev: event{
				SyscallID: int64(unix.SYS_OPEN),
				Ret:       4,
				ArgCount:  1,
				ArgTypes:  [6]uint8{varArgString},
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
			want: "open(\"/var/\"...) = 4",
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
