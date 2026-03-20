package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	trace "litrace/internal"
	"litrace/internal/bpf"
	"litrace/internal/cli"

	"golang.org/x/sys/unix"
)

type childWaitResult struct {
	err       error
	status    syscall.WaitStatus
	hasStatus bool
}

func signalName(sig syscall.Signal) string {
	name := unix.SignalName(unix.Signal(sig))
	if name != "" {
		return name
	}
	return fmt.Sprintf("SIG%d", sig)
}

func formatExitLine(ws syscall.WaitStatus) string {
	if ws.Exited() {
		return fmt.Sprintf("+++ exited with %d +++", ws.ExitStatus())
	}

	if ws.Signaled() {
		line := fmt.Sprintf("+++ killed by %s", signalName(ws.Signal()))
		if ws.CoreDump() {
			line += " (core dumped)"
		}
		return line + " +++"
	}

	return "+++ exited with ? +++"
}

func exitWithWaitStatus(ws syscall.WaitStatus) {
	if ws.Exited() {
		os.Exit(ws.ExitStatus())
	}

	if ws.Signaled() {
		sig := ws.Signal()
		signal.Reset(sig)
		_ = syscall.Kill(syscall.Getpid(), sig)
		os.Exit(128 + int(sig))
	}

	os.Exit(1)
}

func main() {
	exeName := os.Args[0]

	cfg, err := cli.ParseArgs(exeName, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	traceOutput := io.Writer(os.Stderr)
	if cfg.TraceOutputPath != "" {
		file, err := os.Create(cfg.TraceOutputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to open trace output %s: %w", cfg.TraceOutputPath, err))
			os.Exit(1)
		}
		defer file.Close()
		traceOutput = file
	}

	cmd := exec.Command(cfg.ProgramPath, cfg.ProgramArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to start %s: %w", cfg.ProgramName, err))
		os.Exit(1)
	}

	pid := cmd.Process.Pid

	runtime.LockOSThread()
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, syscall.WALL, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to wait for child stop: %w", err))
		os.Exit(1)
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("unexpected wait status: %v", ws))
		os.Exit(1)
	}

	tgid := uint32(pid)
	handle, err := bpf.NewHandle(tgid, bpf.HandleConfig{
		FollowForks:     cfg.FollowForks,
		TraceSyscallIDs: cfg.TraceSyscallIDs,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, err)
		os.Exit(1)
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, closeErr)
		}
	}()

	if err := syscall.PtraceDetach(pid); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to resume child: %w", err))
		os.Exit(1)
	}
	runtime.UnlockOSThread()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		syscall.Kill(-pid, syscall.SIGKILL)
	}()

	done := make(chan childWaitResult, 1)
	go func() {
		waitErr := cmd.Wait()
		result := childWaitResult{err: waitErr}
		if cmd.ProcessState != nil {
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
				result.status = ws
				result.hasStatus = true
			}
		}
		done <- result
		_ = handle.CloseReader()
	}()

	for {
		rawEvent, err := handle.ReadEvent()
		if err != nil {
			if bpf.IsReaderClosed(err) {
				break
			}
			fmt.Fprintf(os.Stderr, "%s: reading event: %v\n", exeName, err)
			continue
		}

		ev, err := trace.DecodeEvent(rawEvent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: decoding event: %v\n", exeName, err)
			continue
		}
		fmt.Fprintf(traceOutput, "%s\n", trace.FormatOutputLine(ev, tgid))
	}

	waitResult := <-done
	if waitResult.err != nil {
		if _, ok := waitResult.err.(*exec.ExitError); !ok {
			fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to wait for child exit: %w", waitResult.err))
			os.Exit(1)
		}
	}

	if !waitResult.hasStatus {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to determine child wait status"))
		os.Exit(1)
	}

	fmt.Fprintf(traceOutput, "%s\n", formatExitLine(waitResult.status))
	exitWithWaitStatus(waitResult.status)
}
