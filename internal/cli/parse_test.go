package cli

import (
	"strings"
	"testing"
)

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
