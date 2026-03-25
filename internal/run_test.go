// SPDX-License-Identifier: GPL-2.0-or-later

package trace

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeSignal struct{}

func (fakeSignal) Signal() {}

func (fakeSignal) String() string { return "fake" }

func TestRunRequiresTraceOutput(t *testing.T) {
	t.Parallel()

	_, err := Run(Config{}, Options{})
	if err == nil {
		t.Fatal("Run returned nil error, want trace output validation error")
	}
	if !strings.Contains(err.Error(), "trace output writer is required") {
		t.Fatalf("Run error = %q, want trace output validation error", err)
	}
}

func TestRunRequiresLaunchOrAttachTarget(t *testing.T) {
	t.Parallel()

	_, err := Run(Config{}, Options{TraceOutput: io.Discard})
	if err == nil {
		t.Fatal("Run returned nil error, want configuration validation error")
	}
	if !strings.Contains(err.Error(), "requires a program path or attach PID") {
		t.Fatalf("Run error = %q, want configuration validation error", err)
	}
}

func TestRunRejectsMixedLaunchAndAttachModes(t *testing.T) {
	t.Parallel()

	_, err := Run(Config{
		ProgramPath: "/bin/echo",
		AttachPIDs:  []int{123},
	}, Options{TraceOutput: io.Discard})
	if err == nil {
		t.Fatal("Run returned nil error, want mixed-mode validation error")
	}
	if !strings.Contains(err.Error(), "cannot mix attach PIDs with a launched program") {
		t.Fatalf("Run error = %q, want mixed-mode validation error", err)
	}
}

func TestAddSummaryEvent(t *testing.T) {
	t.Parallel()

	summary := make(map[int64]syscallSummary)

	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_OPENAT), Ret: 3, Dur: 5000})
	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_OPENAT), Ret: -int64(unix.ENOENT), Dur: 7000})
	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_CLOSE), Ret: 0, Dur: 2000})

	openat := summary[int64(unix.SYS_OPENAT)]
	if openat.Calls != 2 || openat.Errors != 1 || openat.TotalNs != 12000 {
		t.Fatalf("openat summary = %+v, want calls=2 errors=1 totalNs=12000", openat)
	}

	closeStats := summary[int64(unix.SYS_CLOSE)]
	if closeStats.Calls != 1 || closeStats.Errors != 0 || closeStats.TotalNs != 2000 {
		t.Fatalf("close summary = %+v, want calls=1 errors=0 totalNs=2000", closeStats)
	}
}

func TestFormatExitLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ws   syscall.WaitStatus
		want string
	}{
		{
			name: "exited",
			ws:   syscall.WaitStatus(7 << 8),
			want: "+++ exited with 7 +++",
		},
		{
			name: "signaled",
			ws:   syscall.WaitStatus(syscall.SIGTERM),
			want: "+++ killed by SIGTERM +++",
		},
		{
			name: "signaled core dump",
			ws:   syscall.WaitStatus(syscall.SIGSEGV | 0x80),
			want: "+++ killed by SIGSEGV (core dumped) +++",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := FormatExitLine(tt.ws)
			if got != tt.want {
				t.Fatalf("FormatExitLine(%#x) = %q, want %q", uint32(tt.ws), got, tt.want)
			}
		})
	}
}

func TestSignalAsSyscall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sig    os.Signal
		want   syscall.Signal
		wantOK bool
	}{
		{
			name:   "syscall signal",
			sig:    syscall.SIGINT,
			want:   syscall.SIGINT,
			wantOK: true,
		},
		{
			name:   "nil signal",
			sig:    nil,
			wantOK: false,
		},
		{
			name:   "non syscall signal",
			sig:    fakeSignal{},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := signalAsSyscall(tt.sig)
			if ok != tt.wantOK {
				t.Fatalf("signalAsSyscall(%v) ok = %v, want %v", tt.sig, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("signalAsSyscall(%v) = %v, want %v", tt.sig, got, tt.want)
			}
		})
	}
}

func TestForwardLaunchSignal(t *testing.T) {
	t.Parallel()

	t.Run("forwards syscall signal", func(t *testing.T) {
		t.Parallel()

		var gotPID int
		var gotSig syscall.Signal
		called := false

		forwardLaunchSignal(321, syscall.SIGTERM, func(pid int, sig syscall.Signal) error {
			called = true
			gotPID = pid
			gotSig = sig
			return nil
		})

		if !called {
			t.Fatal("forwardLaunchSignal did not invoke sender")
		}
		if gotPID != 321 || gotSig != syscall.SIGTERM {
			t.Fatalf("forwardLaunchSignal sent (%d, %v), want (%d, %v)", gotPID, gotSig, 321, syscall.SIGTERM)
		}
	})

	t.Run("ignores non syscall signal", func(t *testing.T) {
		t.Parallel()

		called := false
		forwardLaunchSignal(321, fakeSignal{}, func(pid int, sig syscall.Signal) error {
			called = true
			return nil
		})
		if called {
			t.Fatal("forwardLaunchSignal should ignore non-syscall signals")
		}
	})

	t.Run("ignores esrch", func(t *testing.T) {
		t.Parallel()

		called := false
		forwardLaunchSignal(321, syscall.SIGINT, func(pid int, sig syscall.Signal) error {
			called = true
			return syscall.ESRCH
		})
		if !called {
			t.Fatal("forwardLaunchSignal did not invoke sender")
		}
	})

	t.Run("swallows other sender errors", func(t *testing.T) {
		t.Parallel()

		called := false
		forwardLaunchSignal(321, syscall.SIGINT, func(pid int, sig syscall.Signal) error {
			called = true
			return errors.New("boom")
		})
		if !called {
			t.Fatal("forwardLaunchSignal did not invoke sender")
		}
	})
}
