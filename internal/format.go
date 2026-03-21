package trace

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"litrace/internal/syscalls"

	"golang.org/x/sys/unix"
)

type enumEntry struct {
	value uint64
	name  string
}

type flagEntry struct {
	value uint64
	name  string
}

type syscallFormatter struct {
	formatArg         func(ev Event, idx int) (string, bool)
	effectiveArgCount func(ev Event) int
}

var openModeAccess = []enumEntry{
	{value: unix.O_RDONLY, name: "O_RDONLY"},
	{value: unix.O_WRONLY, name: "O_WRONLY"},
	{value: unix.O_RDWR, name: "O_RDWR"},
}

var openModeFlags = []flagEntry{
	{value: unix.O_APPEND, name: "O_APPEND"},
	{value: unix.O_ASYNC, name: "O_ASYNC"},
	{value: unix.O_CLOEXEC, name: "O_CLOEXEC"},
	{value: unix.O_CREAT, name: "O_CREAT"},
	{value: unix.O_DIRECT, name: "O_DIRECT"},
	{value: unix.O_EXCL, name: "O_EXCL"},
	{value: unix.O_NOATIME, name: "O_NOATIME"},
	{value: unix.O_NOCTTY, name: "O_NOCTTY"},
	{value: unix.O_NOFOLLOW, name: "O_NOFOLLOW"},
	{value: unix.O_NONBLOCK, name: "O_NONBLOCK"},
	{value: unix.O_PATH, name: "O_PATH"},
	{value: unix.O_SYNC, name: "O_SYNC"},
	{value: unix.O_TMPFILE, name: "O_TMPFILE"},
	{value: unix.O_DIRECTORY, name: "O_DIRECTORY"},
	{value: unix.O_DSYNC, name: "O_DSYNC"},
	{value: unix.O_TRUNC, name: "O_TRUNC"},
}

var mmapProtFlags = []flagEntry{
	{value: unix.PROT_READ, name: "PROT_READ"},
	{value: unix.PROT_WRITE, name: "PROT_WRITE"},
	{value: unix.PROT_EXEC, name: "PROT_EXEC"},
}

var mmapFlags = []flagEntry{
	{value: unix.MAP_SHARED, name: "MAP_SHARED"},
	{value: unix.MAP_PRIVATE, name: "MAP_PRIVATE"},
	{value: unix.MAP_FIXED, name: "MAP_FIXED"},
	{value: unix.MAP_ANON, name: "MAP_ANONYMOUS"},
	{value: unix.MAP_POPULATE, name: "MAP_POPULATE"},
	{value: unix.MAP_NONBLOCK, name: "MAP_NONBLOCK"},
	{value: unix.MAP_STACK, name: "MAP_STACK"},
	{value: unix.MAP_HUGETLB, name: "MAP_HUGETLB"},
	{value: unix.MAP_DENYWRITE, name: "MAP_DENYWRITE"},
	{value: unix.MAP_EXECUTABLE, name: "MAP_EXECUTABLE"},
	{value: unix.MAP_LOCKED, name: "MAP_LOCKED"},
	{value: unix.MAP_GROWSDOWN, name: "MAP_GROWSDOWN"},
	{value: unix.MAP_NORESERVE, name: "MAP_NORESERVE"},
}

var syscallFormatters = map[int64]syscallFormatter{
	int64(unix.SYS_MMAP): {
		formatArg: formatMmapArg,
	},
	int64(unix.SYS_OPEN): {
		formatArg:         formatOpenArg(1, -1),
		effectiveArgCount: effectiveOpenArgCount(1, 2),
	},
	int64(unix.SYS_OPENAT): {
		formatArg:         formatOpenArg(2, 0),
		effectiveArgCount: effectiveOpenArgCount(2, 3),
	},
	int64(unix.SYS_STAT): {
		formatArg: formatStatArg(1, formatCapturedStat),
	},
	int64(unix.SYS_LSTAT): {
		formatArg: formatStatArg(1, formatCapturedStat),
	},
	int64(unix.SYS_FSTAT): {
		formatArg: formatStatArg(1, formatCapturedStat),
	},
	int64(unix.SYS_NEWFSTATAT): {
		formatArg: formatAtStatArg(2, formatCapturedStat),
	},
	int64(unix.SYS_STATX): {
		formatArg: formatAtStatArg(4, formatCapturedStatx),
	},
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

func formatRetDefault(ret int64) string {
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

func formatRet(ev Event) string {
	if ev.Ret < 0 {
		return formatRetDefault(ev.Ret)
	}

	switch ev.SyscallID {
	case int64(unix.SYS_MMAP):
		return formatPtr(uint64(ev.Ret))
	case int64(unix.SYS_UMASK):
		return formatMode(uint64(ev.Ret))
	}

	return formatRetDefault(ev.Ret)
}

func formatMode(raw uint64) string {
	return fmt.Sprintf("%#03o", uint32(raw)&0xffff)
}

func formatStatMode(mode uint32) string {
	fileType := formatStatFileType(mode)
	perms := fmt.Sprintf("%#03o", mode&07777)
	if fileType == "" {
		return perms
	}
	return fileType + "|" + perms
}

func formatStatFileType(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "S_IFREG"
	case unix.S_IFDIR:
		return "S_IFDIR"
	case unix.S_IFLNK:
		return "S_IFLNK"
	case unix.S_IFCHR:
		return "S_IFCHR"
	case unix.S_IFBLK:
		return "S_IFBLK"
	case unix.S_IFIFO:
		return "S_IFIFO"
	case unix.S_IFSOCK:
		return "S_IFSOCK"
	default:
		return ""
	}
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

func formatPtr(raw uint64) string {
	if raw == 0 {
		return "NULL"
	}
	return fmt.Sprintf("0x%x", raw)
}

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

func formatOutputLine(ev Event, rootTGID uint32) string {
	return FormatOutputLine(ev, rootTGID)
}

type SummaryRow struct {
	Syscall string
	Calls   uint64
	Errors  uint64
	TotalNs uint64
}

func FormatSummary(summary map[int64]*syscallSummary) string {
	rows := make([]SummaryRow, 0, len(summary))
	var totalCalls uint64
	var totalErrors uint64
	var totalNs uint64

	for syscallID, stats := range summary {
		rows = append(rows, SummaryRow{
			Syscall: syscalls.Name(syscallID),
			Calls:   stats.Calls,
			Errors:  stats.Errors,
			TotalNs: stats.TotalNs,
		})
		totalCalls += stats.Calls
		totalErrors += stats.Errors
		totalNs += stats.TotalNs
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalNs != rows[j].TotalNs {
			return rows[i].TotalNs > rows[j].TotalNs
		}
		return rows[i].Syscall < rows[j].Syscall
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%% time     seconds  usecs/call     calls    errors syscall\n")
	fmt.Fprintf(&b, "------ ----------- ----------- --------- --------- ----------------\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%6.2f %11.6f %11d %9d %9d %s\n",
			summaryPercent(row.TotalNs, totalNs),
			float64(row.TotalNs)/1e9,
			summaryUsecsPerCall(row.TotalNs, row.Calls),
			row.Calls,
			row.Errors,
			row.Syscall,
		)
	}
	fmt.Fprintf(&b, "------ ----------- ----------- --------- --------- ----------------\n")
	fmt.Fprintf(&b, "%6.2f %11.6f %11d %9d %9d total\n",
		summaryPercent(totalNs, totalNs),
		float64(totalNs)/1e9,
		summaryUsecsPerCall(totalNs, totalCalls),
		totalCalls,
		totalErrors,
	)

	return b.String()
}

func summaryPercent(totalNs, allNs uint64) float64 {
	if allNs == 0 {
		return 0
	}
	return (float64(totalNs) * 100) / float64(allNs)
}

func summaryUsecsPerCall(totalNs, calls uint64) uint64 {
	if calls == 0 {
		return 0
	}
	return totalNs / 1000 / calls
}
