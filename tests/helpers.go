package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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

	litracePath := filepath.Join(root, "litrace")
	mustExist(t, litracePath, fixturePath)

	traceFile, err := os.CreateTemp(t.TempDir(), "litrace-trace-*.out")
	if err != nil {
		t.Fatalf("create trace output file: %v", err)
	}
	if err := traceFile.Close(); err != nil {
		t.Fatalf("close trace output file: %v", err)
	}

	cmd := exec.Command(litracePath, "-e", filter, "-o", traceFile.Name(), fixturePath)
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
