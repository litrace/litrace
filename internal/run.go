package trace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"litrace/internal/bpf"

	"golang.org/x/sys/unix"
)

type Config struct {
	ProgramName     string
	ProgramPath     string
	ProgramArgs     []string
	FollowForks     bool
	TraceSyscallIDs map[int64]struct{}
}

type Options struct {
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	TraceOutput io.Writer
	Signals     <-chan os.Signal
}

type ChildWaitResult struct {
	Err       error
	Status    syscall.WaitStatus
	HasStatus bool
}

func signalName(sig syscall.Signal) string {
	name := unix.SignalName(unix.Signal(sig))
	if name != "" {
		return name
	}
	return fmt.Sprintf("SIG%d", sig)
}

func FormatExitLine(ws syscall.WaitStatus) string {
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

func Run(cfg Config, opts Options) (ws syscall.WaitStatus, err error) {
	if opts.TraceOutput == nil {
		return 0, fmt.Errorf("trace output writer is required")
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}

	cmd := exec.Command(cfg.ProgramPath, cfg.ProgramArgs...)
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.Stdin = opts.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start %s: %w", cfg.ProgramName, err)
	}

	pid := cmd.Process.Pid

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var startWS syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &startWS, syscall.WALL, nil); err != nil {
		return 0, fmt.Errorf("failed to wait for child stop: %w", err)
	}
	if !startWS.Stopped() || startWS.StopSignal() != syscall.SIGTRAP {
		return 0, fmt.Errorf("unexpected wait status: %v", startWS)
	}

	tgid := uint32(pid)
	handle, err := bpf.NewHandle(tgid, bpf.HandleConfig{
		FollowForks:     cfg.FollowForks,
		TraceSyscallIDs: cfg.TraceSyscallIDs,
	})
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close trace handle: %w", closeErr))
		}
	}()

	if err := syscall.PtraceDetach(pid); err != nil {
		return 0, fmt.Errorf("failed to resume child: %w", err)
	}

	done := make(chan ChildWaitResult, 1)
	go func() {
		waitErr := cmd.Wait()
		result := ChildWaitResult{Err: waitErr}
		if cmd.ProcessState != nil {
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
				result.Status = ws
				result.HasStatus = true
			}
		}
		done <- result
		_ = handle.CloseReader()
	}()

	if opts.Signals != nil {
		go killProcessGroupOnSignal(opts.Signals, pid)
	}

	for {
		rawEvent, err := handle.ReadEvent()
		if err != nil {
			if bpf.IsReaderClosed(err) {
				break
			}
			fmt.Fprintf(opts.Stderr, "litrace: reading event: %v\n", err)
			continue
		}

		ev, err := DecodeEvent(rawEvent)
		if err != nil {
			fmt.Fprintf(opts.Stderr, "litrace: decoding event: %v\n", err)
			continue
		}
		fmt.Fprintf(opts.TraceOutput, "%s\n", FormatOutputLine(ev, tgid))
	}

	waitResult := <-done
	if waitResult.Err != nil {
		if _, ok := waitResult.Err.(*exec.ExitError); !ok {
			return 0, fmt.Errorf("failed to wait for child exit: %w", waitResult.Err)
		}
	}

	if !waitResult.HasStatus {
		return 0, fmt.Errorf("failed to determine child wait status")
	}

	fmt.Fprintf(opts.TraceOutput, "%s\n", FormatExitLine(waitResult.Status))
	return waitResult.Status, nil
}

func killProcessGroupOnSignal(signals <-chan os.Signal, pid int) {
	sig, ok := <-signals
	if !ok || sig == nil {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
