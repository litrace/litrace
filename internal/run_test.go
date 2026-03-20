package trace

import (
	"io"
	"strings"
	"syscall"
	"testing"
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
