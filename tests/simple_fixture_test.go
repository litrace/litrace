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

func TestClockGettime(t *testing.T) {
	runSimpleFixtureMatch(t, "clock_gettime", "trace=clock_gettime")
}

func TestEventfd(t *testing.T) {
	runSimpleFixtureMatch(t, "eventfd", "trace=eventfd")
}

func TestLseek(t *testing.T) {
	runSimpleFixtureMatch(t, "lseek", "trace=lseek")
}

func TestUmask(t *testing.T) {
	runSimpleFixtureMatch(t, "umask", "trace=umask")
}

func TestZeroArgBasic(t *testing.T) {
	runSimpleFixtureMatch(t, "zero_arg", "trace=getpid,getppid,getuid,getgid,sched_yield")
}
