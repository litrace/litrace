package tests

import (
	"path/filepath"
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
