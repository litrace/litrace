package main

import (
	"testing"

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
