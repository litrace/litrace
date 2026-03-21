// SPDX-License-Identifier: GPL-2.0-or-later

package trace

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHandleTraceSyscallIDsPathFilterSupport(t *testing.T) {
	t.Parallel()

	got := handleTraceSyscallIDs(Config{
		TracePaths: []string{"/tmp/target"},
		TraceSyscallIDs: map[int64]struct{}{
			int64(unix.SYS_READ): {},
		},
	})

	for _, want := range []int64{
		int64(unix.SYS_READ),
		int64(unix.SYS_OPEN),
		int64(unix.SYS_OPENAT),
		int64(unix.SYS_CLOSE),
		int64(unix.SYS_DUP),
		int64(unix.SYS_DUP2),
		int64(unix.SYS_DUP3),
		int64(unix.SYS_FCNTL),
		int64(unix.SYS_CHDIR),
		int64(unix.SYS_FCHDIR),
		int64(unix.SYS_RENAME),
		int64(unix.SYS_RENAMEAT),
		int64(unix.SYS_RENAMEAT2),
		int64(unix.SYS_UNLINK),
		int64(unix.SYS_UNLINKAT),
		int64(unix.SYS_ACCESS),
		int64(unix.SYS_STAT),
		int64(unix.SYS_LSTAT),
		int64(unix.SYS_NEWFSTATAT),
		int64(unix.SYS_FACCESSAT),
		int64(unix.SYS_STATX),
		int64(unix.SYS_OPENAT2),
		int64(unix.SYS_FACCESSAT2),
	} {
		if _, ok := got[want]; !ok {
			t.Fatalf("handleTraceSyscallIDs missing %d", want)
		}
	}
}

func TestPathFilterTracksFDLifecycle(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{TracePaths: []string{"/tmp/target"}})

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), "/tmp/target", 3)
	if !filter.shouldOutput(openEv) {
		t.Fatal("matched open should be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       4,
		ArgCount:  3,
		Args:      [6]uint64{3, 0, 4},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("read on tracked fd should be printed")
	}

	dupEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_DUP),
		Ret:       7,
		ArgCount:  1,
		Args:      [6]uint64{3},
		ArgTypes:  [6]uint8{argFD},
	}
	if !filter.shouldOutput(dupEv) {
		t.Fatal("dup on tracked fd should be printed")
	}

	closeDup := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_CLOSE),
		Ret:       0,
		ArgCount:  1,
		Args:      [6]uint64{7},
		ArgTypes:  [6]uint8{argFD},
	}
	if !filter.shouldOutput(closeDup) {
		t.Fatal("close on tracked duplicate should be printed")
	}

	if filter.shouldOutput(closeDup) {
		t.Fatal("closed duplicate fd should not remain tracked")
	}
}

func TestPathFilterDisabledPassesThrough(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{})
	ev := Event{SyscallID: int64(unix.SYS_CLOSE)}
	if !filter.shouldOutput(ev) {
		t.Fatal("path filter disabled should pass events through")
	}
}

func TestPathFilterDoesNotSeedUnmatchedOpen(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{TracePaths: []string{"/tmp/target"}})

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPENAT), "/tmp/other", 3)
	if filter.shouldOutput(openEv) {
		t.Fatal("unmatched openat should not be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       4,
		ArgCount:  3,
		Args:      [6]uint64{3, 0, 4},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if filter.shouldOutput(readEv) {
		t.Fatal("read on unmatched fd should not be printed")
	}
}

func TestPathFilterHonorsUserVisibleTraceSelector(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{
		TracePaths: []string{"/tmp/target"},
		TraceSyscallIDs: map[int64]struct{}{
			int64(unix.SYS_READ): {},
		},
	})

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), "/tmp/target", 3)
	if filter.shouldOutput(openEv) {
		t.Fatal("support open should seed tracking without being printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       4,
		ArgCount:  3,
		Args:      [6]uint64{3, 0, 4},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("user-selected read on tracked fd should be printed")
	}
}

func TestPathFilterDup2ReplacesTrackedFD(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{TracePaths: []string{"/tmp/target"}})

	if !filter.shouldOutput(pathFilterOpenEvent(int64(unix.SYS_OPEN), "/tmp/target", 3)) {
		t.Fatal("matched open should be printed")
	}
	if !filter.shouldOutput(pathFilterOpenEvent(int64(unix.SYS_OPEN), "/tmp/target", 8)) {
		t.Fatal("second matched open should be printed")
	}

	dup2Ev := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_DUP2),
		Ret:       8,
		ArgCount:  2,
		Args:      [6]uint64{9, 8},
		ArgTypes:  [6]uint8{argFD, argFD},
	}
	if !filter.shouldOutput(dup2Ev) {
		t.Fatal("dup2 touching tracked newfd should be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{8, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if filter.shouldOutput(readEv) {
		t.Fatal("dup2 from untracked source should clear tracking on newfd")
	}
}

func TestPathFilterMatchesTaggedFDArgs(t *testing.T) {
	t.Parallel()

	filter := newPathFilter(Config{TracePaths: []string{"/tmp/target"}})

	if !filter.shouldOutput(pathFilterOpenEvent(int64(unix.SYS_OPEN), "/tmp/target", 1)) {
		t.Fatal("matched open should be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       0,
		ArgCount:  3,
		Args:      [6]uint64{0xfacefeed00000000 | 1, 0, 0},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("tagged read fd should match tracked fd")
	}

	writeEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_WRITE),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{0xfacefeed00000000 | 1, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(writeEv) {
		t.Fatal("tagged write fd should match tracked fd")
	}
}

func TestPathFilterResolvesRelativePathsAgainstProcessCWD(t *testing.T) {
	t.Parallel()

	target := filepath.Clean("/tmp/litrace-relative/target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})
	filter.cwdByPID[100] = filepath.Dir(target)

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), filepath.Base(target), 5)
	if !filter.shouldOutput(openEv) {
		t.Fatal("relative open should match against cached cwd")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{5, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("read on fd opened from relative path should be printed")
	}
}

func TestPathFilterResolvesOpenatRelativeToTrackedDirFD(t *testing.T) {
	t.Parallel()

	baseDir := filepath.Clean("/tmp/litrace-openat-dir")
	target := filepath.Join(baseDir, "target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})

	dirOpen := pathFilterOpenEvent(int64(unix.SYS_OPEN), baseDir, 10)
	if filter.shouldOutput(dirOpen) {
		t.Fatal("opening unmatched base directory should not be printed")
	}

	openatEv := pathFilterOpenAtEvent(10, "target.txt", 11)
	if !filter.shouldOutput(openatEv) {
		t.Fatal("openat relative to tracked dirfd should match target path")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{11, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("read on fd opened through dirfd-relative openat should be printed")
	}
}

func TestPathFilterUpdatesCWDOnChdir(t *testing.T) {
	t.Parallel()

	target := filepath.Clean("/tmp/litrace-chdir/target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})
	filter.cwdByPID[100] = "/tmp"

	chdirEv := pathFilterSinglePathEvent(int64(unix.SYS_CHDIR), filepath.Dir(target), 0)
	if filter.shouldOutput(chdirEv) {
		t.Fatal("chdir to parent directory should not match target file path")
	}

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), filepath.Base(target), 5)
	if !filter.shouldOutput(openEv) {
		t.Fatal("relative open after chdir should match target path")
	}
}

func TestPathFilterUpdatesCWDOnFchdir(t *testing.T) {
	t.Parallel()

	target := filepath.Clean("/tmp/litrace-fchdir/target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})
	filter.setFDPath(100, 9, filepath.Dir(target))

	fchdirEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_FCHDIR),
		Ret:       0,
		ArgCount:  1,
		Args:      [6]uint64{9},
		ArgTypes:  [6]uint8{argFD},
	}
	if filter.shouldOutput(fchdirEv) {
		t.Fatal("fchdir to parent directory should not match target file path")
	}

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), filepath.Base(target), 5)
	if !filter.shouldOutput(openEv) {
		t.Fatal("relative open after fchdir should match target path")
	}
}

func TestPathFilterRenameMovesTrackedFDState(t *testing.T) {
	t.Parallel()

	oldPath := filepath.Clean("/tmp/litrace-rename/old.txt")
	newPath := filepath.Clean("/tmp/litrace-rename/new.txt")
	filter := newPathFilter(Config{TracePaths: []string{newPath}})
	filter.cwdByPID[100] = filepath.Dir(oldPath)

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), filepath.Base(oldPath), 5)
	if filter.shouldOutput(openEv) {
		t.Fatal("open on pre-rename source path should not match target path")
	}

	renameEv := pathFilterRenameEvent(int64(unix.SYS_RENAME), filepath.Base(oldPath), filepath.Base(newPath), 0)
	if !filter.shouldOutput(renameEv) {
		t.Fatal("rename into target path should be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{5, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("fd opened before rename into target path should become tracked")
	}
}

func TestPathFilterUnlinkClearsTrackedFDState(t *testing.T) {
	t.Parallel()

	target := filepath.Clean("/tmp/litrace-unlink/target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})

	openEv := pathFilterOpenEvent(int64(unix.SYS_OPEN), target, 5)
	if !filter.shouldOutput(openEv) {
		t.Fatal("matched open should be printed")
	}

	unlinkEv := pathFilterSinglePathEvent(int64(unix.SYS_UNLINK), target, 0)
	if !filter.shouldOutput(unlinkEv) {
		t.Fatal("unlink of target path should be printed")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{5, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if filter.shouldOutput(readEv) {
		t.Fatal("unlink should clear tracked fd state for the removed path")
	}
}

func TestPathFilterMatchesNewfstatatRelativeToTrackedDirFD(t *testing.T) {
	t.Parallel()

	baseDir := filepath.Clean("/tmp/litrace-newfstatat-dir")
	target := filepath.Join(baseDir, "target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})

	dirOpen := pathFilterOpenEvent(int64(unix.SYS_OPEN), baseDir, 10)
	if filter.shouldOutput(dirOpen) {
		t.Fatal("opening unmatched base directory should not be printed")
	}

	statEv := pathFilterAtPathEvent(int64(unix.SYS_NEWFSTATAT), 10, 1, "target.txt", 0)
	if !filter.shouldOutput(statEv) {
		t.Fatal("newfstatat relative to tracked dirfd should match target path")
	}
}

func TestPathFilterOpenat2SeedsTrackedFDs(t *testing.T) {
	t.Parallel()

	baseDir := filepath.Clean("/tmp/litrace-openat2-dir")
	target := filepath.Join(baseDir, "target.txt")
	filter := newPathFilter(Config{TracePaths: []string{target}})

	dirOpen := pathFilterOpenEvent(int64(unix.SYS_OPEN), baseDir, 10)
	if filter.shouldOutput(dirOpen) {
		t.Fatal("opening unmatched base directory should not be printed")
	}

	openEv := pathFilterAtPathEvent(int64(unix.SYS_OPENAT2), 10, 1, "target.txt", 11)
	openEv.ArgCount = 4
	openEv.ArgTypes = [6]uint8{argFD, varArgString, argPtr, argUint}
	if !filter.shouldOutput(openEv) {
		t.Fatal("openat2 relative to tracked dirfd should match target path")
	}

	readEv := Event{
		Pid:       100,
		SyscallID: int64(unix.SYS_READ),
		Ret:       1,
		ArgCount:  3,
		Args:      [6]uint64{11, 0, 1},
		ArgTypes:  [6]uint8{argFD, argPtr, argUint},
	}
	if !filter.shouldOutput(readEv) {
		t.Fatal("read on fd opened through openat2 should be printed")
	}
}

func pathFilterOpenEvent(syscallID int64, path string, ret int64) Event {
	ev := Event{
		Pid:        100,
		SyscallID:  syscallID,
		Ret:        ret,
		ArgCount:   4,
		ArgTypes:   [6]uint8{varArgString, argFlags, argMode},
		VarCount:   1,
		PayloadLen: uint16(len(path)),
	}

	argIndex := uint8(0)
	if syscallID == int64(unix.SYS_OPENAT) {
		ev.ArgCount = 4
		ev.ArgTypes = [6]uint8{argFD, varArgString, argFlags, argMode}
		argIndex = 1
	}

	ev.VarDesc[0] = VarArgDesc{
		ArgIndex: argIndex,
		Length:   uint16(len(path)),
	}
	copy(ev.Payload[:], []byte(path))
	return ev
}

func pathFilterOpenAtEvent(dirfd uint64, path string, ret int64) Event {
	ev := pathFilterOpenEvent(int64(unix.SYS_OPENAT), path, ret)
	ev.Args[0] = dirfd
	return ev
}

func pathFilterSinglePathEvent(syscallID int64, path string, ret int64) Event {
	ev := Event{
		Pid:        100,
		SyscallID:  syscallID,
		Ret:        ret,
		ArgCount:   1,
		ArgTypes:   [6]uint8{varArgString},
		VarCount:   1,
		PayloadLen: uint16(len(path)),
	}
	ev.VarDesc[0] = VarArgDesc{
		ArgIndex: 0,
		Length:   uint16(len(path)),
	}
	copy(ev.Payload[:], []byte(path))
	return ev
}

func pathFilterRenameEvent(syscallID int64, oldPath, newPath string, ret int64) Event {
	ev := Event{
		Pid:       100,
		SyscallID: syscallID,
		Ret:       ret,
		ArgCount:  2,
		ArgTypes:  [6]uint8{varArgString, varArgString},
		VarCount:  2,
	}
	ev.VarDesc[0] = VarArgDesc{
		ArgIndex: 0,
		Length:   uint16(len(oldPath)),
	}
	ev.VarDesc[1] = VarArgDesc{
		ArgIndex: 1,
		Offset:   uint16(len(oldPath)),
		Length:   uint16(len(newPath)),
	}
	ev.PayloadLen = uint16(len(oldPath) + len(newPath))
	copy(ev.Payload[:], []byte(oldPath))
	copy(ev.Payload[len(oldPath):], []byte(newPath))
	return ev
}

func pathFilterAtPathEvent(syscallID int64, dirfd uint64, argIndex uint8, path string, ret int64) Event {
	ev := Event{
		Pid:        100,
		SyscallID:  syscallID,
		Ret:        ret,
		ArgCount:   2,
		Args:       [6]uint64{dirfd},
		ArgTypes:   [6]uint8{argFD, varArgString},
		VarCount:   1,
		PayloadLen: uint16(len(path)),
	}
	ev.VarDesc[0] = VarArgDesc{
		ArgIndex: argIndex,
		Length:   uint16(len(path)),
	}
	copy(ev.Payload[:], []byte(path))
	return ev
}
