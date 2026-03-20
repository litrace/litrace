package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	trace "litrace/internal"
)

func TestAttachExistingProcess(t *testing.T) {
	requireRoot(t)

	root := repoRoot(t)
	litracePath := filepath.Join(root, "litrace")
	fixturePath := filepath.Join(root, "tests", "fixtures", "bin", "attach_umask")
	mustExist(t, litracePath, fixturePath)

	traceFile, err := os.CreateTemp(t.TempDir(), "litrace-attach-*.out")
	if err != nil {
		t.Fatalf("create trace output file: %v", err)
	}
	traceFilePath := traceFile.Name()
	if err := traceFile.Close(); err != nil {
		t.Fatalf("close trace output file: %v", err)
	}

	fixtureCmd := exec.Command(fixturePath)
	fixtureStdin, err := fixtureCmd.StdinPipe()
	if err != nil {
		t.Fatalf("open fixture stdin: %v", err)
	}
	var fixtureStdout bytes.Buffer
	var fixtureStderr bytes.Buffer
	fixtureCmd.Stdout = &fixtureStdout
	fixtureCmd.Stderr = &fixtureStderr

	if err := fixtureCmd.Start(); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer func() {
		if fixtureCmd.ProcessState == nil || !fixtureCmd.ProcessState.Exited() {
			_ = fixtureCmd.Process.Kill()
			_, _ = fixtureCmd.Process.Wait()
		}
	}()

	litraceCmd := exec.Command(litracePath, "-e", "trace=umask", "-o", traceFilePath, "-p", strconv.Itoa(fixtureCmd.Process.Pid))
	litraceCmd.Dir = root
	var litraceOutput bytes.Buffer
	litraceCmd.Stdout = &litraceOutput
	litraceCmd.Stderr = &litraceOutput

	if err := litraceCmd.Start(); err != nil {
		t.Fatalf("start litrace attach: %v", err)
	}

	if _, err := fixtureStdin.Write([]byte{'\n'}); err != nil {
		t.Fatalf("release fixture: %v", err)
	}
	if err := fixtureStdin.Close(); err != nil {
		t.Fatalf("close fixture stdin: %v", err)
	}

	if err := fixtureCmd.Wait(); err != nil {
		t.Fatalf("wait for fixture: %v\nfixture stderr:\n%s", err, fixtureStderr.Bytes())
	}
	if len(fixtureStderr.Bytes()) != 0 {
		t.Fatalf("unexpected fixture stderr:\n%s", fixtureStderr.Bytes())
	}

	if err := litraceCmd.Wait(); err != nil {
		t.Fatalf("wait for litrace attach: %v\noutput:\n%s", err, litraceOutput.Bytes())
	}

	traceOutput, err := os.ReadFile(traceFilePath)
	if err != nil {
		t.Fatalf("read trace output file: %v", err)
	}

	lines := splitNonEmptyLines(traceOutput)
	if len(lines) == 0 {
		t.Fatalf("expected attach trace output, got none")
	}

	wantZeroLine := regexp.MustCompile(`^umask\(000\) = 022$`)
	wantRestoreLine := regexp.MustCompile(`^umask\(022\) = 000$`)
	foundZero := false
	foundRestore := false
	for _, line := range lines {
		if wantZeroLine.MatchString(line) {
			foundZero = true
		}
		if wantRestoreLine.MatchString(line) {
			foundRestore = true
		}
	}
	if !foundZero || !foundRestore {
		t.Fatalf("expected attach trace to contain both umask lines\ntrace output:\n%s", traceOutput)
	}

	fixtureLines := splitNonEmptyLines(fixtureStdout.Bytes())
	if len(fixtureLines) != 100 {
		t.Fatalf("unexpected fixture stdout line count: got %d want %d\noutput:\n%s", len(fixtureLines), 100, fixtureStdout.Bytes())
	}
	for i, line := range fixtureLines {
		if !wantZeroLine.MatchString(strings.TrimSpace(line)) {
			t.Fatalf("unexpected fixture stdout line %d: %q", i+1, line)
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "+++ ") {
			if line != trace.FormatExitLine(syscall.WaitStatus(0)) {
				t.Fatalf("unexpected attach exit line %q", line)
			}
		}
	}
}
