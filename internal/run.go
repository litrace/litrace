package trace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"time"

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

	launchDone := make(chan ChildWaitResult, 1)
	attachDone := make(chan attachResult, 1)
	var rootTGID uint32
	var targetTGIDs []uint32
	var launchPID int
	var launchCmd *exec.Cmd
	var launchNeedsResume bool
	if len(cfg.AttachPIDs) > 0 {
		if err := validateAttachTargets(cfg.AttachPIDs); err != nil {
			return 0, err
		}
		rootTGID = rootTracePID(cfg.AttachPIDs, 0)
		targetTGIDs = traceTargetTGIDs(cfg.AttachPIDs, 0)
	} else {
		launchCmd, launchPID, err = startLaunchTrace(cfg, opts)
		if err != nil {
			return 0, err
		}
		launchNeedsResume = true
		rootTGID = rootTracePID(nil, launchPID)
		targetTGIDs = traceTargetTGIDs(nil, launchPID)
	}

	handle, err := bpf.NewHandle(targetTGIDs, bpf.HandleConfig{
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

	if len(cfg.AttachPIDs) > 0 {
		startAttachMonitor(handle, cfg.AttachPIDs, opts.Signals, attachDone)
	} else {
		if launchNeedsResume {
			if err := syscall.PtraceDetach(launchPID); err != nil {
				return 0, fmt.Errorf("failed to resume child: %w", err)
			}
		}
		startLaunchMonitor(handle, opts.Signals, launchPID)
		startLaunchWait(handle, launchCmd, launchDone)
	}

	summary := make(map[int64]*syscallSummary)
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
		if !shouldOutputEvent(cfg, ev) {
			continue
		}
		if cfg.SummaryOnly {
			addSummaryEvent(summary, ev)
			continue
		}
		fmt.Fprintf(opts.TraceOutput, "%s\n", FormatOutputLine(ev, rootTGID))
	}

	if len(cfg.AttachPIDs) > 0 {
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

func startLaunchTrace(cfg Config, opts Options) (*exec.Cmd, int, error) {
	cmd := exec.Command(cfg.ProgramPath, cfg.ProgramArgs...)
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.Stdin = opts.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("failed to start %s: %w", cfg.ProgramName, err)
	}

	var startWS syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &startWS, syscall.WALL, nil); err != nil {
		return nil, 0, fmt.Errorf("failed to wait for child stop: %w", err)
	}
	if !startWS.Stopped() || startWS.StopSignal() != syscall.SIGTRAP {
		return nil, 0, fmt.Errorf("unexpected wait status: %v", startWS)
	}

	return cmd, cmd.Process.Pid, nil
}

func startLaunchWait(handle *bpf.Handle, cmd *exec.Cmd, done chan<- ChildWaitResult) {
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
}

func startLaunchMonitor(handle *bpf.Handle, signals <-chan os.Signal, pid int) {
	go func() {
		sig, ok := <-signals
		if ok && sig != nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		_ = handle.CloseReader()
	}()
}

func validateAttachTargets(pids []int) error {
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err != nil && err != syscall.EPERM {
			return fmt.Errorf("failed to access pid %d: %w", pid, err)
		}
	}
	return nil
}

func startAttachMonitor(handle *bpf.Handle, attachPIDs []int, signals <-chan os.Signal, done chan<- attachResult) {
	pids := slices.Clone(attachPIDs)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			if !anyProcessAlive(pids) {
				done <- attachResult{Status: syscall.WaitStatus(0)}
				_ = handle.CloseReader()
				return
			}

			select {
			case sig, ok := <-signals:
				done <- attachResult{Status: signalWaitStatus(sig, ok)}
				_ = handle.CloseReader()
				return
			case <-ticker.C:
			}
		}
	}()
}

func anyProcessAlive(pids []int) bool {
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			return true
		}
	}
	return false
}

func signalWaitStatus(sig os.Signal, ok bool) syscall.WaitStatus {
	if !ok || sig == nil {
		return syscall.WaitStatus(0)
	}
	switch s := sig.(type) {
	case syscall.Signal:
		return syscall.WaitStatus(s)
	default:
		return syscall.WaitStatus(0)
	}
}

func rootTracePID(attachPIDs []int, launchPID int) uint32 {
	if len(attachPIDs) == 1 {
		return uint32(attachPIDs[0])
	}
	if len(attachPIDs) > 1 {
		return 0
	}
	return uint32(launchPID)
}

func traceTargetTGIDs(attachPIDs []int, launchPID int) []uint32 {
	if len(attachPIDs) > 0 {
		targets := make([]uint32, 0, len(attachPIDs))
		for _, pid := range attachPIDs {
			targets = append(targets, uint32(pid))
		}
		return targets
	}
	return []uint32{uint32(launchPID)}
}

func shouldOutputEvent(cfg Config, ev Event) bool {
	if len(cfg.TracePaths) == 0 {
		return true
	}

	path, ok := eventTracePath(ev)
	if !ok {
		return false
	}

	for _, candidate := range cfg.TracePaths {
		if candidate == path {
			return true
		}
	}
	return false
}

func eventTracePath(ev Event) (string, bool) {
	var argIndex int

	switch ev.SyscallID {
	case int64(unix.SYS_OPEN):
		argIndex = 0
	case int64(unix.SYS_OPENAT):
		argIndex = 1
	default:
		return "", false
	}

	desc, ok := findVarArgDesc(ev, argIndex)
	if !ok {
		return "", false
	}
	if desc.Flags != varFlagNone {
		return "", false
	}

	payload, ok := varPayloadSlice(ev, desc)
	if !ok {
		return "", false
	}

	return string(payload), true
}
