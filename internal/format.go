// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
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
