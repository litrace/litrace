package trace

import (
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
