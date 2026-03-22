// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
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

func formatStatArg(idx int, decode func([]byte) (string, bool)) func(Event, int) (string, bool) {
	return func(ev Event, argIdx int) (string, bool) {
		if argIdx != idx || ev.Ret < 0 {
			return "", false
		}

		desc, ok := findVarArgDesc(ev, argIdx)
		if !ok {
			return "", false
		}
		if desc.Flags != varFlagNone {
			return "<?>", true
		}

		payload, ok := varPayloadSlice(ev, desc)
		if !ok {
			return "<?>", true
		}

		rendered, ok := decode(payload)
		if !ok {
			return "<?>", true
		}
		return rendered, true
	}
}

func formatAtStatArg(resultIdx int, decode func([]byte) (string, bool)) func(Event, int) (string, bool) {
	statArg := formatStatArg(resultIdx, decode)
	return func(ev Event, argIdx int) (string, bool) {
		if argIdx == 0 {
			return formatDirFD(ev.Args[argIdx]), true
		}
		return statArg(ev, argIdx)
	}
}

func formatCapturedStat(payload []byte) (string, bool) {
	var st unix.Stat_t
	size := int(unsafe.Sizeof(st))
	if len(payload) < size {
		return "", false
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(&st)), size), payload[:size])

	return fmt.Sprintf("{st_mode=%s, st_size=%d, ...}",
		formatStatMode(uint32(st.Mode)),
		st.Size,
	), true
}

func formatCapturedStatx(payload []byte) (string, bool) {
	var stx unix.Statx_t
	size := int(unsafe.Sizeof(stx))
	if len(payload) < size {
		return "", false
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(&stx)), size), payload[:size])

	return fmt.Sprintf("{stx_mode=%s, stx_size=%d, ...}",
		formatStatMode(uint32(stx.Mode)),
		stx.Size,
	), true
}
