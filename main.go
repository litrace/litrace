package main

//go:generate go tool bpf2go tracer tracer.c

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	exeName := os.Args[0]

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%s\n", fmt.Errorf("usage: %s <program> [args...]", exeName))
		os.Exit(1)
	}

	path, err := exec.LookPath(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", fmt.Errorf("%s: %w", os.Args[1], err))
		os.Exit(1)
	}

	cmd := exec.Command(path, os.Args[2:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to start %s: %w", os.Args[1], err))
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

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to load BPF objects: %w", err))
		os.Exit(1)
	}
	defer objs.Close()

	tgid := uint32(pid)
	val := uint8(1)
	if err := objs.TargetPids.Put(tgid, val); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to populate PID map: %w", err))
		os.Exit(1)
	}

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to attach tracepoint: %w", err))
		os.Exit(1)
	}
	defer tp.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		syscall.Kill(-pid, syscall.SIGKILL)
	}()

	if err := syscall.PtraceDetach(pid); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to resume child: %w", err))
		os.Exit(1)
	}
	runtime.UnlockOSThread()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to wait for child exit: %w", err))
		os.Exit(1)
	}
}
