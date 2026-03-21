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
		wantAttach   []int
		wantPaths    []string
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
			wantErr: "usage: litrace [-f] [-o FILE] [-p PID[,PID...]] [-P PATH] <program> [args...]",
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
		{
			name:       "supports attach mode without program",
			args:       []string{"-p", "123"},
			wantAttach: []int{123},
		},
		{
			name:    "rejects mixing attach mode with program",
			args:    []string{"-p", "123", "/bin/echo"},
			wantErr: "cannot use -p with a program",
		},
		{
			name:         "supports trace path before program",
			args:         []string{"-P", "/tmp/target", "/bin/echo", "hi"},
			wantPaths:    []string{"/tmp/target"},
			wantProgName: "/bin/echo",
			wantProgPath: "/bin/echo",
			wantProgArgs: []string{"hi"},
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
			if len(cfg.AttachPIDs) != len(tt.wantAttach) {
				t.Fatalf("ParseArgs() AttachPIDs length mismatch: got %d want %d", len(cfg.AttachPIDs), len(tt.wantAttach))
			}
			for i := range cfg.AttachPIDs {
				if cfg.AttachPIDs[i] != tt.wantAttach[i] {
					t.Fatalf("ParseArgs() AttachPIDs[%d] mismatch: got %d want %d", i, cfg.AttachPIDs[i], tt.wantAttach[i])
				}
			}
			if len(cfg.TracePaths) != len(tt.wantPaths) {
				t.Fatalf("ParseArgs() TracePaths length mismatch: got %d want %d", len(cfg.TracePaths), len(tt.wantPaths))
			}
			for i := range cfg.TracePaths {
				if cfg.TracePaths[i] != tt.wantPaths[i] {
					t.Fatalf("ParseArgs() TracePaths[%d] mismatch: got %q want %q", i, cfg.TracePaths[i], tt.wantPaths[i])
				}
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

func TestParseArgsAttachFilter(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantPIDs   []int
		wantErr    string
		wantTrace  []int64
	}{
		{
			name:      "single attach pid",
			args:      []string{"-p", "42"},
			wantPIDs:  []int{42},
		},
		{
			name:      "comma separated attach pids",
			args:      []string{"-p", "42,84"},
			wantPIDs:  []int{42, 84},
		},
		{
			name:      "repeated attach expressions deduplicate",
			args:      []string{"-p", "42,84", "-p", "84", "-p", "126"},
			wantPIDs:  []int{42, 84, 126},
		},
		{
			name:      "attach mode can combine with trace filter",
			args:      []string{"-p", "42", "-e", "trace=read"},
			wantPIDs:  []int{42},
			wantTrace: []int64{0},
		},
		{
			name:    "empty attach expression",
			args:    []string{"-p", ""},
			wantErr: "empty PID list",
		},
		{
			name:    "empty pid token",
			args:    []string{"-p", "42,,84"},
			wantErr: "empty PID",
		},
		{
			name:    "non numeric pid",
			args:    []string{"-p", "abc"},
			wantErr: "invalid -p PID \"abc\"",
		},
		{
			name:    "non positive pid",
			args:    []string{"-p", "0"},
			wantErr: "invalid -p PID \"0\"",
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
			if len(cfg.AttachPIDs) != len(tt.wantPIDs) {
				t.Fatalf("ParseArgs() AttachPIDs length mismatch: got %d want %d", len(cfg.AttachPIDs), len(tt.wantPIDs))
			}
			for i := range cfg.AttachPIDs {
				if cfg.AttachPIDs[i] != tt.wantPIDs[i] {
					t.Fatalf("ParseArgs() AttachPIDs[%d] mismatch: got %d want %d", i, cfg.AttachPIDs[i], tt.wantPIDs[i])
				}
			}
			requireTraceIDs(t, cfg.TraceSyscallIDs, tt.wantTrace...)
			if cfg.ProgramName != "" || cfg.ProgramPath != "" || len(cfg.ProgramArgs) != 0 {
				t.Fatalf("ParseArgs() expected empty program fields in attach mode, got ProgramName=%q ProgramPath=%q ProgramArgs=%v", cfg.ProgramName, cfg.ProgramPath, cfg.ProgramArgs)
			}
		})
	}
}

func TestParseArgsTracePath(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantPaths []string
		wantErr   string
		wantTrace []int64
	}{
		{
			name:      "single path selector",
			args:      []string{"-P", "/tmp/one", "/bin/echo"},
			wantPaths: []string{"/tmp/one"},
		},
		{
			name:      "repeated path selectors preserve order",
			args:      []string{"-P", "/tmp/one", "-P", "relative/path", "-P", "/tmp/one", "/bin/echo"},
			wantPaths: []string{"/tmp/one", "relative/path", "/tmp/one"},
		},
		{
			name:      "path selector combines with trace selector",
			args:      []string{"-P", "/tmp/one", "-e", "trace=openat", "/bin/echo"},
			wantPaths: []string{"/tmp/one"},
			wantTrace: []int64{257},
		},
		{
			name:    "empty path rejected",
			args:    []string{"-P", "", "/bin/echo"},
			wantErr: "invalid -P path \"\": empty path",
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
			if len(cfg.TracePaths) != len(tt.wantPaths) {
				t.Fatalf("ParseArgs() TracePaths length mismatch: got %d want %d", len(cfg.TracePaths), len(tt.wantPaths))
			}
			for i := range cfg.TracePaths {
				if cfg.TracePaths[i] != tt.wantPaths[i] {
					t.Fatalf("ParseArgs() TracePaths[%d] mismatch: got %q want %q", i, cfg.TracePaths[i], tt.wantPaths[i])
				}
			}
			requireTraceIDs(t, cfg.TraceSyscallIDs, tt.wantTrace...)
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
