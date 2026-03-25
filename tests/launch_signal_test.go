// SPDX-License-Identifier: GPL-2.0-or-later

package tests

import (
	"bytes"
	"fmt"
	trace "litrace/internal"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLaunchModeForwardsOriginalSignal(t *testing.T) {
	requireRoot(t)

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("resolve sh path: %v", err)
	}

	tests := []struct {
		name       string
		sig        syscall.Signal
		wantStatus int
	}{
		{
			name:       "sigint",
			sig:        syscall.SIGINT,
			wantStatus: 42,
		},
		{
			name:       "sigterm",
			sig:        syscall.SIGTERM,
			wantStatus: 43,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readyPath := filepath.Join(t.TempDir(), "ready")
			script := "trap 'exit 42' INT; trap 'exit 43' TERM; : > \"$1\"; while :; do sleep 1; done"

			signals := make(chan os.Signal, 1)
			var traceOutput bytes.Buffer
			var fixtureStdout bytes.Buffer
			var fixtureStderr bytes.Buffer

			resultCh := make(chan struct {
				ws  syscall.WaitStatus
				err error
			}, 1)

			go func() {
				ws, err := trace.Run(trace.Config{
					ProgramName: "sh",
					ProgramPath: shPath,
					ProgramArgs: []string{"-c", script, "sh", readyPath},
				}, trace.Options{
					Stdout:      &fixtureStdout,
					Stderr:      &fixtureStderr,
					TraceOutput: &traceOutput,
					Signals:     signals,
				})
				resultCh <- struct {
					ws  syscall.WaitStatus
					err error
				}{ws: ws, err: err}
			}()

			if err := waitForFile(readyPath, 5*time.Second); err != nil {
				t.Fatalf("wait for signal-ready child: %v\nfixture stderr:\n%s\ntrace output:\n%s", err, fixtureStderr.Bytes(), traceOutput.Bytes())
			}

			signals <- tt.sig

			select {
			case result := <-resultCh:
				if result.err != nil {
					t.Fatalf("trace.Run() error: %v\nfixture stderr:\n%s\ntrace output:\n%s", result.err, fixtureStderr.Bytes(), traceOutput.Bytes())
				}
				if !result.ws.Exited() {
					t.Fatalf("child did not exit normally after %s: %v\nfixture stderr:\n%s\ntrace output:\n%s", tt.sig, result.ws, fixtureStderr.Bytes(), traceOutput.Bytes())
				}
				if result.ws.ExitStatus() != tt.wantStatus {
					t.Fatalf("child exit status after %s = %d, want %d\nfixture stderr:\n%s\ntrace output:\n%s", tt.sig, result.ws.ExitStatus(), tt.wantStatus, fixtureStderr.Bytes(), traceOutput.Bytes())
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out waiting for trace.Run() to exit after %s\nfixture stderr:\n%s\ntrace output:\n%s", tt.sig, fixtureStderr.Bytes(), traceOutput.Bytes())
			}
		})
	}
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}
