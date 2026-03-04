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
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type event struct {
	Ts          uint64
	SyscallID   int64
	Ret         int64
	Args        [6]uint64
	VarDesc     [6]varArgDesc
	Payload     [512]byte
	Pid         uint32
	Tid         uint32
	Seq         uint32
	PayloadLen  uint16
	ArgCount    uint8
	VarCount    uint8
	ArgTypes    [6]uint8
	VarReserved uint8
}

type varArgDesc struct {
	ArgIndex uint8
	Flags    uint8
	Offset   uint16
	Length   uint16
	Reserved uint16
}

const (
	argNone  uint8 = 0
	argInt   uint8 = 1
	argUint  uint8 = 2
	argFD    uint8 = 3
	argMode  uint8 = 4
	argFlags uint8 = 5
	argOff   uint8 = 6
	argPtr   uint8 = 7
	argRaw   uint8 = 255
)

const (
	varArgNone   uint8 = 0
	varArgString uint8 = 1
	varArgBytes  uint8 = 2
	varArgArgv   uint8 = 3
)

const (
	varFlagNone        uint8 = 0
	varFlagTruncated   uint8 = 1 << 0
	varFlagReadError   uint8 = 1 << 1
	varFlagNullPointer uint8 = 1 << 2
)

func isVarArgEnabled(ev event, idx int) bool {
	if idx < 0 || idx >= len(ev.ArgTypes) {
		return false
	}
	for i := 0; i < int(ev.VarCount) && i < len(ev.VarDesc); i++ {
		if int(ev.VarDesc[i].ArgIndex) == idx {
			return ev.ArgTypes[idx] >= varArgString && ev.ArgTypes[idx] <= varArgArgv
		}
	}
	return false
}

func findVarArgDesc(ev event, idx int) (varArgDesc, bool) {
	for i := 0; i < int(ev.VarCount) && i < len(ev.VarDesc); i++ {
		desc := ev.VarDesc[i]
		if int(desc.ArgIndex) == idx {
			return desc, true
		}
	}
	return varArgDesc{}, false
}

func formatVarString(ev event, desc varArgDesc) string {
	if desc.Flags&varFlagNullPointer != 0 {
		return "NULL"
	}
	if desc.Flags&varFlagReadError != 0 {
		return "<?>"
	}

	payloadLen := int(ev.PayloadLen)
	if payloadLen > len(ev.Payload) {
		payloadLen = len(ev.Payload)
	}

	start := int(desc.Offset)
	end := start + int(desc.Length)
	if start < 0 || end < start || end > payloadLen {
		return "<?>"
	}

	quoted := strconv.QuoteToASCII(string(ev.Payload[start:end]))
	if desc.Flags&varFlagTruncated != 0 {
		return quoted + "..."
	}
	return quoted
}

func formatVarBytes(ev event, desc varArgDesc) string {
	if desc.Flags&varFlagNullPointer != 0 {
		return "NULL"
	}
	if desc.Flags&varFlagReadError != 0 {
		return "<?>"
	}

	payloadLen := int(ev.PayloadLen)
	if payloadLen > len(ev.Payload) {
		payloadLen = len(ev.Payload)
	}

	start := int(desc.Offset)
	end := start + int(desc.Length)
	if start < 0 || end < start || end > payloadLen {
		return "<?>"
	}

	quoted := strconv.QuoteToASCII(string(ev.Payload[start:end]))
	if desc.Flags&varFlagTruncated != 0 {
		return quoted + "..."
	}
	return quoted
}

func formatVarArg(ev event, idx int) (string, bool) {
	if !isVarArgEnabled(ev, idx) {
		return "", false
	}

	desc, ok := findVarArgDesc(ev, idx)
	if !ok {
		return "", false
	}

	switch ev.ArgTypes[idx] {
	case varArgString:
		return formatVarString(ev, desc), true
	case varArgBytes:
		return formatVarBytes(ev, desc), true
	default:
		return "<?>", true
	}
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

func formatMode(raw uint64) string {
	return fmt.Sprintf("0%o", uint32(raw)&0xffff)
}

func formatWhence(raw uint64) string {
	whence := int64(int32(raw))
	switch whence {
	case unix.SEEK_SET:
		return "SEEK_SET"
	case unix.SEEK_CUR:
		return "SEEK_CUR"
	case unix.SEEK_END:
		return "SEEK_END"
	case unix.SEEK_DATA:
		return "SEEK_DATA"
	case unix.SEEK_HOLE:
		return "SEEK_HOLE"
	default:
		return fmt.Sprintf("%d", whence)
	}
}

func formatArg(ev event, idx int) string {
	if rendered, ok := formatVarArg(ev, idx); ok {
		return rendered
	}

	typ := ev.ArgTypes[idx]
	raw := ev.Args[idx]

	switch typ {
	case argFD:
		return fmt.Sprintf("%d", int64(int32(raw)))
	case argInt:
		if ev.SyscallID == int64(unix.SYS_LSEEK) && idx == 2 {
			return formatWhence(raw)
		}
		return fmt.Sprintf("%d", int64(int32(raw)))
	case argUint:
		return fmt.Sprintf("%d", raw)
	case argMode:
		return formatMode(raw)
	case argFlags:
		return fmt.Sprintf("0x%x", raw)
	case argOff:
		return fmt.Sprintf("%d", int64(raw))
	case argPtr:
		return fmt.Sprintf("0x%x", raw)
	case argRaw:
		return fmt.Sprintf("0x%x", raw)
	case argNone:
		return "?"
	default:
		return fmt.Sprintf("0x%x", raw)
	}
}

func formatArgs(ev event) string {
	count := int(ev.ArgCount)
	if count > len(ev.Args) {
		count = len(ev.Args)
	}

	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		parts = append(parts, formatArg(ev, i))
	}
	return strings.Join(parts, ", ")
}

func formatEventLine(ev event) string {
	return fmt.Sprintf("%s(%s) = %s", syscallName(ev.SyscallID), formatArgs(ev), formatRet(ev.Ret))
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
		fmt.Fprintf(os.Stderr, "%s\n", formatEventLine(ev))
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
