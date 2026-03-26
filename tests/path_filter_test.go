// SPDX-License-Identifier: GPL-2.0-or-later

package tests

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
)

func TestTracePathOpenat(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", "path_filter_openat")

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=openat",
		"-P", "/tmp/litrace_path_filter_match.tmp",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestTracePathFDLifecycle(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "path_filter_fd")

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-P", "/tmp/litrace_path_filter_fd_match.tmp",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestTracePathOpenatDirFDRelative(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "path_filter_openat_dirfd")

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=openat",
		"-P", "/tmp/litrace_path_filter_dirfd/target.tmp",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestTracePathRelativeAfterChdir(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "path_filter_chdir")

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=open,chdir",
		"-P", "/tmp/litrace_path_filter_chdir/target.tmp",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestTracePathNewfstatatDirFDRelative(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "path_filter_newfstatat")

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=newfstatat",
		"-P", "/tmp/litrace_path_filter_newfstatat/target.tmp",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestTracePathFollowForksInheritsDirFDState(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "path_filter_fork_openat_dirfd")
	targetPath := "/tmp/litrace_path_filter_fork_dirfd/target.tmp"

	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-f",
		"-e", "trace=openat",
		"-P", targetPath,
	)

	childPID := parseSinglePIDLine(t, fixtureOutput)
	lines := splitNonEmptyLines(traceOutput)
	if len(lines) != 2 {
		t.Fatalf("unexpected trace line count: got %d want 2\ntrace output:\n%s", len(lines), traceOutput)
	}

	wantOpenat := regexp.MustCompile(fmt.Sprintf(`^\[pid %d\] openat\(\d+, "target\.tmp", O_RDONLY\) = \d+$`, childPID))
	if !wantOpenat.MatchString(lines[0]) {
		t.Fatalf("unexpected child openat line: got %q\ntrace output:\n%s", lines[0], traceOutput)
	}
	if lines[1] != "+++ exited with 0 +++" {
		t.Fatalf("unexpected exit line: got %q want %q\ntrace output:\n%s", lines[1], "+++ exited with 0 +++", traceOutput)
	}
}
