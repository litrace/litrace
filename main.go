package main

//go:generate go tool bpf2go tracer tracer.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type event struct {
	Ts        uint64
	Pid       uint32
	Tid       uint32
	SyscallID int64
	Ret       int64
}

func formatRet(ret int64) string {
	if ret >= 0 {
		return fmt.Sprintf("%d", ret)
	}
	errno := syscall.Errno(-ret)
	name := unix.ErrnoName(errno)
	if name == "" {
		return fmt.Sprintf("-1 (error %d)", -ret)
	}
	return fmt.Sprintf("-1 %s (%s)", name, errno.Error())
}

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

	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to attach sys_enter tracepoint: %w", err))
		os.Exit(1)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSysExit, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to attach sys_exit tracepoint: %w", err))
		os.Exit(1)
	}
	defer tpExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to open ring buffer reader: %w", err))
		os.Exit(1)
	}
	defer rd.Close()

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

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			fmt.Fprintf(os.Stderr, "%s: reading event: %v\n", exeName, err)
			continue
		}

		var ev event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "%s: decoding event: %v\n", exeName, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "%s(...) = %s\n", syscallName(ev.SyscallID), formatRet(ev.Ret))
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
