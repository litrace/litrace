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
)

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
	handle, err := bpf.NewHandle(tgid, cfg.FollowForks)
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

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
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

	waitErr := <-done
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to wait for child exit: %w", waitErr))
		os.Exit(1)
	}
}
