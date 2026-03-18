package trace

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"litrace/internal/syscalls"

	"golang.org/x/sys/unix"
)

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

func isVarArgEnabled(ev Event, idx int) bool {
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

func findVarArgDesc(ev Event, idx int) (VarArgDesc, bool) {
	for i := 0; i < int(ev.VarCount) && i < len(ev.VarDesc); i++ {
		desc := ev.VarDesc[i]
		if int(desc.ArgIndex) == idx {
			return desc, true
		}
	}
	return VarArgDesc{}, false
}

func varPayloadSlice(ev Event, desc VarArgDesc) ([]byte, bool) {
	payloadLen := int(ev.PayloadLen)
	if payloadLen > len(ev.Payload) {
		payloadLen = len(ev.Payload)
	}

	start := int(desc.Offset)
	end := start + int(desc.Length)
	if start < 0 || end < start || end > payloadLen {
		return nil, false
	}

	return ev.Payload[start:end], true
}

func formatVarString(ev Event, desc VarArgDesc) string {
	if desc.Flags&varFlagNullPointer != 0 {
		return "NULL"
	}
	if desc.Flags&varFlagReadError != 0 {
		return "<?>"
	}

	payload, ok := varPayloadSlice(ev, desc)
	if !ok {
		return "<?>"
	}

	quoted := strconv.QuoteToASCII(string(payload))
	if desc.Flags&varFlagTruncated != 0 {
		return quoted + "..."
	}
	return quoted
}

func formatVarBytes(ev Event, desc VarArgDesc) string {
	if desc.Flags&varFlagNullPointer != 0 {
		return "NULL"
	}
	if desc.Flags&varFlagReadError != 0 {
		return "<?>"
	}

	payload, ok := varPayloadSlice(ev, desc)
	if !ok {
		return "<?>"
	}

	quoted := strconv.QuoteToASCII(string(payload))
	if desc.Flags&varFlagTruncated != 0 {
		return quoted + "..."
	}
	return quoted
}

func formatVarArgv(ev Event, desc VarArgDesc) string {
	if desc.Flags&varFlagNullPointer != 0 {
		return "NULL"
	}

	payload, ok := varPayloadSlice(ev, desc)
	if !ok {
		return "<?>"
	}

	parts := make([]string, 0, 8)
	for len(payload) > 0 {
		idx := bytes.IndexByte(payload, 0)
		if idx < 0 {
			parts = append(parts, strconv.QuoteToASCII(string(payload)))
			break
		}
		parts = append(parts, strconv.QuoteToASCII(string(payload[:idx])))
		payload = payload[idx+1:]
	}

	if desc.Flags&varFlagReadError != 0 {
		parts = append(parts, "<?>")
	}

	rendered := "[" + strings.Join(parts, ", ") + "]"
	if desc.Flags&varFlagTruncated != 0 {
		return rendered + "..."
	}
	return rendered
}

func formatVarArg(ev Event, idx int) (string, bool) {
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
	case varArgArgv:
		return formatVarArgv(ev, desc), true
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

func formatArg(ev Event, idx int) string {
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

func formatArgs(ev Event) string {
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

func formatEventLine(ev Event) string {
	return fmt.Sprintf("%s(%s) = %s", syscalls.Name(ev.SyscallID), formatArgs(ev), formatRet(ev.Ret))
}

func formatEventPrefix(ev Event, rootTGID uint32) string {
	if ev.Tid == 0 {
		return ""
	}

	if ev.Pid == rootTGID && ev.Tid == rootTGID {
		return ""
	}

	return fmt.Sprintf("[pid %d] ", ev.Tid)
}

func FormatOutputLine(ev Event, rootTGID uint32) string {
	return formatEventPrefix(ev, rootTGID) + formatEventLine(ev)
}

func formatOutputLine(ev Event, rootTGID uint32) string {
	return FormatOutputLine(ev, rootTGID)
}
