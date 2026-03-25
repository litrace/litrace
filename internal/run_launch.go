// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"litrace/internal/bpf"
)

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

type processGroupSignalSender func(pid int, sig syscall.Signal) error

func sendProcessGroupSignal(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}

func signalAsSyscall(sig os.Signal) (syscall.Signal, bool) {
	syscallSig, ok := sig.(syscall.Signal)
	if !ok || syscallSig == 0 {
		return 0, false
	}
	return syscallSig, true
}

func forwardLaunchSignal(pid int, sig os.Signal, send processGroupSignalSender) {
	syscallSig, ok := signalAsSyscall(sig)
	if !ok {
		return
	}
	if err := send(pid, syscallSig); err != nil && err != syscall.ESRCH {
		return
	}
}

func startLaunchMonitor(handle *bpf.Handle, signals <-chan os.Signal, pid int) {
	go func() {
		sig, ok := <-signals
		if ok && sig != nil {
			forwardLaunchSignal(pid, sig, sendProcessGroupSignal)
		}
		_ = handle.CloseReader()
	}()
}
