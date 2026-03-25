// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"

	"litrace/internal/bpf"
)

type targetMode struct {
	launchPID  int
	launchCmd  *exec.Cmd
	attachPIDs []int
}

func prepareTargetMode(cfg Config, opts Options) (targetMode, uint32, []uint32, error) {
	if len(cfg.AttachPIDs) > 0 {
		if err := validateAttachTargets(cfg.AttachPIDs); err != nil {
			return targetMode{}, 0, nil, err
		}

		mode := targetMode{attachPIDs: slices.Clone(cfg.AttachPIDs)}
		return mode, rootTracePID(mode.attachPIDs, 0), traceTargetTGIDs(mode.attachPIDs, 0), nil
	}

	launchCmd, launchPID, err := startLaunchTrace(cfg, opts)
	if err != nil {
		return targetMode{}, 0, nil, err
	}

	mode := targetMode{launchPID: launchPID, launchCmd: launchCmd}
	return mode, rootTracePID(nil, launchPID), traceTargetTGIDs(nil, launchPID), nil
}

func startTargetModeMonitors(handle *bpf.Handle, signals <-chan os.Signal, mode targetMode) (<-chan ChildWaitResult, <-chan attachResult, error) {
	if mode.isAttach() {
		attachDone := make(chan attachResult, 1)
		startAttachMonitor(handle, mode.attachPIDs, signals, attachDone)
		return nil, attachDone, nil
	}

	if err := syscall.PtraceDetach(mode.launchPID); err != nil {
		return nil, nil, fmt.Errorf("failed to resume child: %w", err)
	}

	launchDone := make(chan ChildWaitResult, 1)
	startLaunchMonitor(handle, signals, mode.launchPID)
	startLaunchWait(handle, mode.launchCmd, launchDone)
	return launchDone, nil, nil
}

func (m targetMode) isAttach() bool {
	return len(m.attachPIDs) > 0
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
