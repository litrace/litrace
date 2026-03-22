// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"strings"

	"litrace/internal/syscalls"

	"golang.org/x/sys/unix"
)

func formatEnum(raw uint64, table []enumEntry, fallback func(uint64) string) string {
	for _, entry := range table {
		if entry.value == raw {
			return entry.name
		}
	}
	return fallback(raw)
}

func formatFlags(raw uint64, zero string, table []flagEntry) string {
	if raw == 0 && zero != "" {
		return zero
	}

	parts := make([]string, 0, len(table)+1)
	remaining := raw
	for _, entry := range table {
		if entry.value == 0 {
			continue
		}
		if remaining&entry.value == entry.value {
			parts = append(parts, entry.name)
			remaining &^= entry.value
		}
	}

	if remaining != 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("0x%x", remaining))
	}

	return strings.Join(parts, "|")
}

func formatDirFD(raw uint64) string {
	fd := int64(int32(raw))
	if fd == unix.AT_FDCWD {
		return "AT_FDCWD"
	}
	return fmt.Sprintf("%d", fd)
}

func formatMmapProt(raw uint64) string {
	if raw == unix.PROT_NONE {
		return "PROT_NONE"
	}
	return formatFlags(raw, "", mmapProtFlags)
}

func formatMmapFlags(raw uint64) string {
	return formatFlags(raw, "", mmapFlags)
}

func formatMmapArg(ev Event, idx int) (string, bool) {
	switch idx {
	case 0:
		return formatPtr(ev.Args[idx]), true
	case 2:
		return formatMmapProt(ev.Args[idx]), true
	case 3:
		return formatMmapFlags(ev.Args[idx]), true
	default:
		return "", false
	}
}

func formatOpenFlags(raw uint64) string {
	const accessMask = unix.O_ACCMODE

	access := formatEnum(raw&accessMask, openModeAccess, func(v uint64) string {
		return fmt.Sprintf("0x%x", v)
	})
	rest := raw &^ accessMask
	if rest == 0 {
		return access
	}

	return access + "|" + formatFlags(rest, "", openModeFlags)
}

func formatOpenArg(flagsIdx int, dirfdIdx int) func(ev Event, idx int) (string, bool) {
	return func(ev Event, idx int) (string, bool) {
		switch idx {
		case flagsIdx:
			return formatOpenFlags(ev.Args[idx]), true
		case dirfdIdx:
			return formatDirFD(ev.Args[idx]), true
		default:
			return "", false
		}
	}
}

func effectiveOpenArgCount(flagsIdx int, modeIdx int) func(ev Event) int {
	return func(ev Event) int {
		count := int(ev.ArgCount)
		if count > len(ev.Args) {
			count = len(ev.Args)
		}
		if count > modeIdx && !openNeedsMode(ev.Args[flagsIdx]) {
			return modeIdx
		}
		return count
	}
}

func lookupSyscallFormatter(ev Event) (syscallFormatter, bool) {
	formatter, ok := syscallFormatters[ev.SyscallID]
	return formatter, ok
}

func formatArgDefault(ev Event, idx int) string {
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
		return formatPtr(raw)
	case argRaw:
		return fmt.Sprintf("0x%x", raw)
	case argNone:
		return "?"
	default:
		return fmt.Sprintf("0x%x", raw)
	}
}

func formatArg(ev Event, idx int) string {
	if formatter, ok := lookupSyscallFormatter(ev); ok && formatter.formatArg != nil {
		if rendered, ok := formatter.formatArg(ev, idx); ok {
			return rendered
		}
	}

	if rendered, ok := formatVarArg(ev, idx); ok {
		return rendered
	}

	return formatArgDefault(ev, idx)
}

func openNeedsMode(flags uint64) bool {
	return flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE
}

func effectiveArgCount(ev Event) int {
	if formatter, ok := lookupSyscallFormatter(ev); ok && formatter.effectiveArgCount != nil {
		return formatter.effectiveArgCount(ev)
	}

	count := int(ev.ArgCount)
	if count > len(ev.Args) {
		count = len(ev.Args)
	}

	return count
}

func formatArgs(ev Event) string {
	count := effectiveArgCount(ev)

	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		parts = append(parts, formatArg(ev, i))
	}
	return strings.Join(parts, ", ")
}

func formatEventLine(ev Event) string {
	return fmt.Sprintf("%s(%s) = %s", syscalls.Name(ev.SyscallID), formatArgs(ev), formatRet(ev))
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
