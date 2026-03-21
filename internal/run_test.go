package trace

import (
	"io"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

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

	summary := make(map[int64]*syscallSummary)

	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_OPENAT), Ret: 3, Dur: 5000})
	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_OPENAT), Ret: -int64(unix.ENOENT), Dur: 7000})
	addSummaryEvent(summary, Event{SyscallID: int64(unix.SYS_CLOSE), Ret: 0, Dur: 2000})

	openat := summary[int64(unix.SYS_OPENAT)]
	if openat == nil {
		t.Fatal("missing openat summary row")
	}
	if openat.Calls != 2 || openat.Errors != 1 || openat.TotalNs != 12000 {
		t.Fatalf("openat summary = %+v, want calls=2 errors=1 totalNs=12000", *openat)
	}

	closeStats := summary[int64(unix.SYS_CLOSE)]
	if closeStats == nil {
		t.Fatal("missing close summary row")
	}
	if closeStats.Calls != 1 || closeStats.Errors != 0 || closeStats.TotalNs != 2000 {
		t.Fatalf("close summary = %+v, want calls=1 errors=0 totalNs=2000", *closeStats)
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
