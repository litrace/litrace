package tests

import (
	"path/filepath"
	"testing"
)

func runSimpleFixtureMatch(t *testing.T, fixtureName, filter string) {
	t.Helper()

	requireRoot(t)

	root := repoRoot(t)
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", fixtureName)
	traceOutput, fixtureOutput := runLitrace(t, root, filter, fixturePath)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestFchmod(t *testing.T) {
	runSimpleFixtureMatch(t, "fchmod", "trace=fchmod")
}

func TestLseek(t *testing.T) {
	runSimpleFixtureMatch(t, "lseek", "trace=lseek")
}

func TestUmask(t *testing.T) {
	runSimpleFixtureMatch(t, "umask", "trace=umask")
}
