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
