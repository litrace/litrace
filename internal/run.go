// SPDX-License-Identifier: GPL-2.0-only

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
	AttachPIDs      []int
	FollowForks     bool
	SummaryOnly     bool
	TraceSyscallIDs map[int64]struct{}
	TracePaths      []string
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

type attachResult struct {
	Status syscall.WaitStatus
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

func FormatAttachLine(pid int) string {
	return fmt.Sprintf("litrace: Process %d attached", pid)
}

func Run(cfg Config, opts Options) (ws syscall.WaitStatus, err error) {
	if opts.TraceOutput == nil {
		return 0, fmt.Errorf("trace output writer is required")
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}

	if len(cfg.AttachPIDs) > 0 && cfg.ProgramPath != "" {
		return 0, fmt.Errorf("trace run config cannot mix attach PIDs with a launched program")
	}
	if len(cfg.AttachPIDs) == 0 && cfg.ProgramPath == "" {
		return 0, fmt.Errorf("trace run config requires a program path or attach PID")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	mode, rootTGID, targetTGIDs, err := prepareTargetMode(cfg, opts)
	if err != nil {
		return 0, err
	}

	filter := newPathFilter(cfg)

	handle, err := bpf.NewHandle(targetTGIDs, bpf.HandleConfig{
		FollowForks:     cfg.FollowForks,
		TraceSyscallIDs: handleTraceSyscallIDs(cfg),
	})
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close trace handle: %w", closeErr))
		}
	}()

	launchDone, attachDone, err := startTargetModeMonitors(handle, opts.Signals, mode)
	if err != nil {
		return 0, err
	}

	summary := make(map[int64]syscallSummary)
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
		if !filter.shouldOutput(ev) {
			continue
		}
		if cfg.SummaryOnly {
			addSummaryEvent(summary, ev)
			continue
		}
		fmt.Fprintf(opts.TraceOutput, "%s\n", FormatOutputLine(ev, rootTGID))
	}

	if mode.isAttach() {
		result := <-attachDone
		if cfg.SummaryOnly {
			fmt.Fprint(opts.TraceOutput, FormatSummary(summary))
		}
		return result.Status, nil
	}

	waitResult := <-launchDone
	if waitResult.Err != nil {
		if _, ok := waitResult.Err.(*exec.ExitError); !ok {
			return 0, fmt.Errorf("failed to wait for child exit: %w", waitResult.Err)
		}
	}
	if !waitResult.HasStatus {
		return 0, fmt.Errorf("failed to determine child wait status")
	}
	if cfg.SummaryOnly {
		fmt.Fprint(opts.TraceOutput, FormatSummary(summary))
	} else {
		fmt.Fprintf(opts.TraceOutput, "%s\n", FormatExitLine(waitResult.Status))
	}
	return waitResult.Status, nil
}
