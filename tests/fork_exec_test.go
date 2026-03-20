package tests

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
)

func TestTraceChildrenAcrossForkExec(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", "fork_exec")

	traceOutput, fixtureStdout, fixtureStderr := runLitraceInProcess(t, fixturePath, true, "execve")
	if len(fixtureStderr) != 0 {
		t.Fatalf("unexpected fixture stderr:\n%s", fixtureStderr)
	}

	childPID := parseSinglePIDLine(t, fixtureStdout)
	lines := splitNonEmptyLines(traceOutput)
	if len(lines) != 2 {
		t.Fatalf("unexpected trace line count: got %d want 2\ntrace output:\n%s", len(lines), traceOutput)
	}

	wantExecve := regexp.MustCompile(fmt.Sprintf(`^\[pid %d\] execve\(.+\) = 0$`, childPID))
	if !wantExecve.MatchString(lines[0]) {
		t.Fatalf("unexpected child execve line: got %q\ntrace output:\n%s", lines[0], traceOutput)
	}
	if lines[1] != "+++ exited with 0 +++" {
		t.Fatalf("unexpected exit line: got %q want %q\ntrace output:\n%s", lines[1], "+++ exited with 0 +++", traceOutput)
	}
}
