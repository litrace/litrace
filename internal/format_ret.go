// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

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
