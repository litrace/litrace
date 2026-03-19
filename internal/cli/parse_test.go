package cli

import (
	"strings"
	"testing"
)

func requireTraceIDs(t *testing.T, got map[int64]struct{}, want ...int64) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("trace syscall ID set size mismatch: got %d want %d", len(got), len(want))
	}

	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("trace syscall ID set missing ID %d", id)
		}
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantFollow   bool
		wantTraceOut string
		wantProgName string
		wantProgPath string
		wantProgArgs []string
		wantErr      string
	}{
		{
			name:    "requires program",
			args:    []string{},
			wantErr: "usage: litrace [-f] [-o FILE] <program> [args...]",
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
			name:         "supports -o trace output file",
			args:         []string{"-o", "/tmp/litrace.out", "/bin/echo", "hi"},
			wantTraceOut: "/tmp/litrace.out",
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
			cfg, err := ParseArgs("litrace", tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseArgs() expected error %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseArgs() error mismatch: got %q want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseArgs() unexpected error: %v", err)
			}
			if cfg.FollowForks != tt.wantFollow {
				t.Fatalf("ParseArgs() FollowForks mismatch: got %v want %v", cfg.FollowForks, tt.wantFollow)
			}
			if cfg.TraceOutputPath != tt.wantTraceOut {
				t.Fatalf("ParseArgs() TraceOutputPath mismatch: got %q want %q", cfg.TraceOutputPath, tt.wantTraceOut)
			}
			if cfg.TraceSyscallIDs == nil {
				t.Fatalf("ParseArgs() TraceSyscallIDs should be initialized")
			}
			if len(cfg.TraceSyscallIDs) != 0 {
				t.Fatalf("ParseArgs() TraceSyscallIDs length mismatch: got %d want %d", len(cfg.TraceSyscallIDs), 0)
			}
			if cfg.ProgramName != tt.wantProgName {
				t.Fatalf("ParseArgs() ProgramName mismatch: got %q want %q", cfg.ProgramName, tt.wantProgName)
			}
			if cfg.ProgramPath != tt.wantProgPath {
				t.Fatalf("ParseArgs() ProgramPath mismatch: got %q want %q", cfg.ProgramPath, tt.wantProgPath)
			}
			if len(cfg.ProgramArgs) != len(tt.wantProgArgs) {
				t.Fatalf("ParseArgs() ProgramArgs length mismatch: got %d want %d", len(cfg.ProgramArgs), len(tt.wantProgArgs))
			}
			for i := range cfg.ProgramArgs {
				if cfg.ProgramArgs[i] != tt.wantProgArgs[i] {
					t.Fatalf("ParseArgs() ProgramArgs[%d] mismatch: got %q want %q", i, cfg.ProgramArgs[i], tt.wantProgArgs[i])
				}
			}
		})
	}
}

func TestParseArgsTraceFilter(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantIDs      []int64
		wantErr      string
		wantProgName string
	}{
		{
			name:         "single syscall selector",
			args:         []string{"-e", "trace=read", "/bin/echo"},
			wantIDs:      []int64{0},
			wantProgName: "/bin/echo",
		},
		{
			name:         "comma-separated selector",
			args:         []string{"-e", "trace=read,write", "/bin/echo"},
			wantIDs:      []int64{0, 1},
			wantProgName: "/bin/echo",
		},
		{
			name:         "repeated -e unions selectors",
			args:         []string{"-e", "trace=read", "-e", "trace=write", "-e", "trace=read", "/bin/echo"},
			wantIDs:      []int64{0, 1},
			wantProgName: "/bin/echo",
		},
		{
			name:    "invalid expression missing trace prefix",
			args:    []string{"-e", "read", "/bin/echo"},
			wantErr: "expected trace=<syscall[,syscall...]>",
		},
		{
			name:    "empty trace selector",
			args:    []string{"-e", "trace=", "/bin/echo"},
			wantErr: "empty trace selector",
		},
		{
			name:    "empty syscall token",
			args:    []string{"-e", "trace=read,,write", "/bin/echo"},
			wantErr: "empty syscall name",
		},
		{
			name:    "trailing comma token",
			args:    []string{"-e", "trace=read,", "/bin/echo"},
			wantErr: "empty syscall name",
		},
		{
			name:    "unknown syscall name",
			args:    []string{"-e", "trace=read,not_a_real_syscall", "/bin/echo"},
			wantErr: "unknown syscall \"not_a_real_syscall\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseArgs("litrace", tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseArgs() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseArgs() error mismatch: got %q want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseArgs() unexpected error: %v", err)
			}
			requireTraceIDs(t, cfg.TraceSyscallIDs, tt.wantIDs...)
			if cfg.ProgramName != tt.wantProgName {
				t.Fatalf("ParseArgs() ProgramName mismatch: got %q want %q", cfg.ProgramName, tt.wantProgName)
			}
		})
	}
}
