// SPDX-License-Identifier: GPL-2.0-or-later

package tests

import (
	"path/filepath"
	"testing"
)

func runSimpleFixtureMatch(t *testing.T, fixtureName, filter string, args ...string) {
	t.Helper()

	requireRoot(t)

	root := repoRoot(t)
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", fixtureName)
	litraceArgs := append([]string{"-e", filter}, args...)
	traceOutput, fixtureOutput := runLitraceArgs(t, root, fixturePath, litraceArgs...)

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

func TestFstat(t *testing.T) {
	runSimpleFixtureMatch(t, "fstat", "trace=fstat", "-P", "fstat_sample_file")
}

func TestStat(t *testing.T) {
	runSimpleFixtureMatch(t, "stat", "trace=stat")
}

func TestLstat(t *testing.T) {
	runSimpleFixtureMatch(t, "lstat", "trace=lstat")
}

func TestOpen(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "open")
	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=open",
		"-P", "open.sample",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
}

func TestOpenat(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	fixturePath := buildFixtureSource(t, root, "openat")
	traceOutput, fixtureOutput := runLitraceArgs(
		t,
		root,
		fixturePath,
		"-e", "trace=openat",
		"-P", "openat.sample",
	)

	assertExactOutput(t, traceOutput, fixtureOutput)
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
