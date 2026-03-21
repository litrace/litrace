// SPDX-License-Identifier: GPL-2.0-or-later

package tests

import (
	"bytes"
	trace "litrace/internal"
	"litrace/internal/syscalls"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges to load eBPF programs")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	return root
}

func mustExist(t *testing.T, paths ...string) {
	t.Helper()

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required binary %q missing: %v", path, err)
		}
	}
}

func runLitrace(t *testing.T, root, filter, fixturePath string) ([]byte, []byte) {
	t.Helper()

	return runLitraceArgs(t, root, fixturePath, "-e", filter)
}

func runLitraceArgs(t *testing.T, root, fixturePath string, args ...string) ([]byte, []byte) {
	t.Helper()

	litracePath := filepath.Join(root, "litrace")
	mustExist(t, litracePath, fixturePath)

	traceFile, err := os.CreateTemp(t.TempDir(), "litrace-trace-*.out")
	if err != nil {
		t.Fatalf("create trace output file: %v", err)
	}
	if err := traceFile.Close(); err != nil {
		t.Fatalf("close trace output file: %v", err)
	}

	cmdArgs := append(append([]string{}, args...), "-o", traceFile.Name(), fixturePath)
	cmd := exec.Command(litracePath, cmdArgs...)
	cmd.Dir = root
	runOutput, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run litrace: %v\noutput:\n%s", err, runOutput)
	}

	traceOutput, err := os.ReadFile(traceFile.Name())
	if err != nil {
		t.Fatalf("read trace output file: %v", err)
	}

	return traceOutput, runOutput
}

func buildFixtureSource(t *testing.T, root, fixtureName string) string {
	t.Helper()

	srcPath := filepath.Join(root, "tests", "fixtures", fixtureName+".c")
	mustExist(t, srcPath)

	outPath := filepath.Join(t.TempDir(), fixtureName)
	cmd := exec.Command("cc", srcPath, "-o", outPath)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fixture %q: %v\noutput:\n%s", fixtureName, err, output)
	}

	return outPath
}

func runLitraceInProcess(t *testing.T, fixturePath string, followForks bool, traceNames ...string) ([]byte, []byte, []byte) {
	t.Helper()

	mustExist(t, fixturePath)

	var traceOutput bytes.Buffer
	var fixtureStdout bytes.Buffer
	var fixtureStderr bytes.Buffer

	ws, err := trace.Run(trace.Config{
		ProgramName:     filepath.Base(fixturePath),
		ProgramPath:     fixturePath,
		FollowForks:     followForks,
		TraceSyscallIDs: traceFilterIDs(t, traceNames...),
	}, trace.Options{
		Stdout:      &fixtureStdout,
		Stderr:      &fixtureStderr,
		TraceOutput: &traceOutput,
	})
	if err != nil {
		t.Fatalf("run litrace in-process: %v\nfixture stderr:\n%s\ntrace output:\n%s", err, fixtureStderr.Bytes(), traceOutput.Bytes())
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Fatalf("unexpected fixture wait status: %v\nfixture stderr:\n%s\ntrace output:\n%s", ws, fixtureStderr.Bytes(), traceOutput.Bytes())
	}

	return traceOutput.Bytes(), fixtureStdout.Bytes(), fixtureStderr.Bytes()
}

func traceFilterIDs(t *testing.T, traceNames ...string) map[int64]struct{} {
	t.Helper()

	ids := make(map[int64]struct{}, len(traceNames))
	for _, name := range traceNames {
		id, ok := syscalls.ID(name)
		if !ok {
			t.Fatalf("unknown syscall name %q", name)
		}
		ids[id] = struct{}{}
	}
	return ids
}

func parseSinglePIDLine(t *testing.T, output []byte) int {
	t.Helper()

	lines := splitNonEmptyLines(output)
	if len(lines) != 1 {
		t.Fatalf("unexpected fixture stdout line count: got %d want 1\noutput:\n%s", len(lines), output)
	}

	pid, err := strconv.Atoi(lines[0])
	if err != nil {
		t.Fatalf("parse child pid %q: %v", lines[0], err)
	}

	return pid
}

func assertExactOutput(t *testing.T, traceOutput, fixtureOutput []byte) {
	t.Helper()

	got := splitNonEmptyLines(traceOutput)
	expected := splitNonEmptyLines(fixtureOutput)

	if len(got) != len(expected) {
		t.Fatalf("unexpected trace line count: got %d want %d\ntrace output:\n%s\nfixture output:\n%s", len(got), len(expected), traceOutput, fixtureOutput)
	}

	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("trace line %d mismatch: got %q want %q\ntrace output:\n%s\nfixture output:\n%s", i+1, got[i], expected[i], traceOutput, fixtureOutput)
		}
	}
}

func splitNonEmptyLines(output []byte) []string {
	raw := strings.Split(string(bytes.TrimSpace(output)), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}
