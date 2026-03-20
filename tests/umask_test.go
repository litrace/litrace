package tests

import (
	"path/filepath"
	"testing"
)

func TestUmask(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", "umask")
	traceOutput, fixtureOutput := runLitrace(t, root, "trace=umask", fixturePath)

	assertExactOutput(t, traceOutput, fixtureOutput)
}
