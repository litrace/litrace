// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type processPathState struct {
	cwd        string
	trackedFDs map[uint64]struct{}
	fdPaths    map[uint64]string
}

type pathFilter struct {
	paths          map[string]struct{}
	stateByPID     map[uint32]*processPathState
	userTraceIDs   map[int64]struct{}
	userTraceAll   bool
	pathFilterMode bool
}

func newPathFilter(cfg Config) *pathFilter {
	filter := &pathFilter{
		paths:          make(map[string]struct{}, len(cfg.TracePaths)),
		stateByPID:     make(map[uint32]*processPathState),
		userTraceIDs:   make(map[int64]struct{}, len(cfg.TraceSyscallIDs)),
		userTraceAll:   len(cfg.TraceSyscallIDs) == 0,
		pathFilterMode: len(cfg.TracePaths) > 0,
	}

	for _, path := range cfg.TracePaths {
		filter.paths[path] = struct{}{}
	}
	for id := range cfg.TraceSyscallIDs {
		filter.userTraceIDs[id] = struct{}{}
	}

	return filter
}

func handleTraceSyscallIDs(cfg Config) map[int64]struct{} {
	if len(cfg.TracePaths) == 0 || len(cfg.TraceSyscallIDs) == 0 {
		return cfg.TraceSyscallIDs
	}

	ids := make(map[int64]struct{}, len(cfg.TraceSyscallIDs)+22)
	for id := range cfg.TraceSyscallIDs {
		ids[id] = struct{}{}
	}

	for _, id := range []int64{
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
		ids[id] = struct{}{}
	}

	return ids
}

func (f *pathFilter) shouldOutput(ev Event) bool {
	if !f.pathFilterMode {
		return true
	}

	shouldPrint := f.shouldPrint(ev)
	f.observe(ev)
	return shouldPrint
}

func (f *pathFilter) shouldPrint(ev Event) bool {
	if !f.userAllows(ev.SyscallID) {
		return false
	}

	if f.matchesPath(ev) {
		return true
	}

	return f.hasTrackedFDArg(ev)
}

func (f *pathFilter) userAllows(syscallID int64) bool {
	if f.userTraceAll {
		return true
	}
	_, ok := f.userTraceIDs[syscallID]
	return ok
}

func (f *pathFilter) observe(ev Event) {
	switch ev.SyscallID {
	case int64(unix.SYS_OPEN):
		f.observeOpen(ev, 0)
	case int64(unix.SYS_OPENAT):
		f.observeOpen(ev, 1)
	case int64(unix.SYS_OPENAT2):
		f.observeOpen(ev, 1)
	case int64(unix.SYS_DUP):
		f.observeDupRet(ev, 0)
	case int64(unix.SYS_DUP2), int64(unix.SYS_DUP3):
		f.observeDupPair(ev)
	case int64(unix.SYS_FCNTL):
		f.observeFcntl(ev)
	case int64(unix.SYS_CLOSE):
		f.observeClose(ev)
	case int64(unix.SYS_CHDIR):
		f.observeChdir(ev)
	case int64(unix.SYS_FCHDIR):
		f.observeFchdir(ev)
	case int64(unix.SYS_RENAME):
		f.observeRename(ev, 0, 1)
	case int64(unix.SYS_RENAMEAT), int64(unix.SYS_RENAMEAT2):
		f.observeRename(ev, 1, 3)
	case int64(unix.SYS_UNLINK):
		f.observeUnlink(ev, 0)
	case int64(unix.SYS_UNLINKAT):
		f.observeUnlink(ev, 1)
	}
}

func (f *pathFilter) observeOpen(ev Event, pathArgIndex int) {
	if ev.Ret < 0 {
		return
	}

	path, ok := f.resolvePathAt(ev, pathArgIndex)
	if !ok {
		return
	}

	f.setFDPath(ev.Pid, uint64(ev.Ret), path)
	f.syncTrackedFD(ev.Pid, uint64(ev.Ret), path)
}

func (f *pathFilter) observeDupRet(ev Event, srcIndex int) {
	if ev.Ret < 0 || srcIndex < 0 || srcIndex >= int(ev.ArgCount) {
		return
	}
	srcFD := normalizeTrackedFD(ev.Args[srcIndex])
	if path, ok := f.fdPath(ev.Pid, srcFD); ok {
		f.setFDPath(ev.Pid, uint64(ev.Ret), path)
		f.syncTrackedFD(ev.Pid, uint64(ev.Ret), path)
	}
	if !f.argTracked(ev, srcIndex) {
		return
	}
	f.trackFD(ev.Pid, uint64(ev.Ret))
}

func (f *pathFilter) observeDupPair(ev Event) {
	if ev.ArgCount < 2 || ev.Ret < 0 {
		return
	}

	oldfd := normalizeTrackedFD(ev.Args[0])
	newfd := normalizeTrackedFD(ev.Args[1])
	if path, ok := f.fdPath(ev.Pid, oldfd); ok {
		f.setFDPath(ev.Pid, newfd, path)
		f.syncTrackedFD(ev.Pid, newfd, path)
	} else {
		f.unsetFDPath(ev.Pid, newfd)
		f.untrackFD(ev.Pid, newfd)
	}
	if f.fdTracked(ev.Pid, oldfd) {
		f.trackFD(ev.Pid, newfd)
		return
	}
	f.untrackFD(ev.Pid, newfd)
}

func (f *pathFilter) observeFcntl(ev Event) {
	if ev.ArgCount < 2 || ev.Ret < 0 || !f.argTracked(ev, 0) {
		return
	}

	cmd := int(ev.Args[1])
	if cmd != unix.F_DUPFD && cmd != unix.F_DUPFD_CLOEXEC {
		return
	}

	if path, ok := f.fdPath(ev.Pid, normalizeTrackedFD(ev.Args[0])); ok {
		f.setFDPath(ev.Pid, uint64(ev.Ret), path)
		f.syncTrackedFD(ev.Pid, uint64(ev.Ret), path)
	}
	f.trackFD(ev.Pid, uint64(ev.Ret))
}

func (f *pathFilter) observeClose(ev Event) {
	if ev.Ret < 0 || ev.ArgCount < 1 {
		return
	}
	fd := normalizeTrackedFD(ev.Args[0])
	f.untrackFD(ev.Pid, fd)
	f.unsetFDPath(ev.Pid, fd)
}

func (f *pathFilter) observeChdir(ev Event) {
	if ev.Ret < 0 {
		return
	}
	path, ok := f.resolvePathAt(ev, 0)
	if !ok {
		return
	}
	f.stateForPID(ev.Pid).cwd = path
}

func (f *pathFilter) observeFchdir(ev Event) {
	if ev.Ret < 0 || ev.ArgCount < 1 {
		return
	}
	path, ok := f.fdPath(ev.Pid, normalizeTrackedFD(ev.Args[0]))
	if !ok {
		return
	}
	f.stateForPID(ev.Pid).cwd = path
}

func (f *pathFilter) observeRename(ev Event, oldIndex, newIndex int) {
	if ev.Ret < 0 {
		return
	}

	oldPath, ok := f.resolvePathAt(ev, oldIndex)
	if !ok {
		return
	}
	newPath, ok := f.resolvePathAt(ev, newIndex)
	if !ok {
		return
	}

	f.rewritePIDPaths(ev.Pid, oldPath, newPath)
}

func (f *pathFilter) observeUnlink(ev Event, pathIndex int) {
	if ev.Ret < 0 {
		return
	}

	path, ok := f.resolvePathAt(ev, pathIndex)
	if !ok {
		return
	}

	f.dropPIDPaths(ev.Pid, path)
}

func (f *pathFilter) hasTrackedFDArg(ev Event) bool {
	for i := 0; i < int(ev.ArgCount) && i < len(ev.ArgTypes); i++ {
		if ev.ArgTypes[i] != argFD {
			continue
		}
		if f.fdTracked(ev.Pid, normalizeTrackedFD(ev.Args[i])) {
			return true
		}
	}
	return false
}

func (f *pathFilter) argTracked(ev Event, idx int) bool {
	if idx < 0 || idx >= int(ev.ArgCount) || idx >= len(ev.ArgTypes) {
		return false
	}
	if ev.ArgTypes[idx] != argFD {
		return false
	}
	return f.fdTracked(ev.Pid, normalizeTrackedFD(ev.Args[idx]))
}

func (f *pathFilter) matchesPath(ev Event) bool {
	switch ev.SyscallID {
	case int64(unix.SYS_OPEN):
		return f.matchesPathAt(ev, 0)
	case int64(unix.SYS_OPENAT), int64(unix.SYS_OPENAT2), int64(unix.SYS_NEWFSTATAT), int64(unix.SYS_FACCESSAT), int64(unix.SYS_STATX), int64(unix.SYS_FACCESSAT2):
		return f.matchesPathAt(ev, 1)
	case int64(unix.SYS_ACCESS), int64(unix.SYS_STAT), int64(unix.SYS_LSTAT), int64(unix.SYS_CHDIR), int64(unix.SYS_UNLINK):
		return f.matchesPathAt(ev, 0)
	case int64(unix.SYS_RENAME):
		return f.matchesPathAt(ev, 0) || f.matchesPathAt(ev, 1)
	case int64(unix.SYS_UNLINKAT):
		return f.matchesPathAt(ev, 1)
	case int64(unix.SYS_RENAMEAT), int64(unix.SYS_RENAMEAT2):
		return f.matchesPathAt(ev, 1) || f.matchesPathAt(ev, 3)
	default:
		return false
	}
}

func (f *pathFilter) matchesPathAt(ev Event, argIndex int) bool {
	path, ok := f.resolvePathAt(ev, argIndex)
	if !ok {
		return false
	}
	_, ok = f.paths[path]
	return ok
}

func (f *pathFilter) resolvePathAt(ev Event, argIndex int) (string, bool) {
	path, ok := eventTracePathAt(ev, argIndex)
	if !ok {
		return "", false
	}
	return f.resolvePath(ev, argIndex, path)
}

func (f *pathFilter) resolvePath(ev Event, argIndex int, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), true
	}

	base, ok := f.resolvePathBase(ev, argIndex)
	if !ok {
		return "", false
	}
	return filepath.Clean(filepath.Join(base, path)), true
}

func (f *pathFilter) resolvePathBase(ev Event, argIndex int) (string, bool) {
	dirfdArgIndex, ok := pathBaseFDArgIndex(ev.SyscallID, argIndex)
	if !ok {
		return f.cwdForPID(ev.Pid)
	}
	if dirfdArgIndex < 0 {
		return f.cwdForPID(ev.Pid)
	}
	if dirfdArgIndex >= int(ev.ArgCount) {
		return "", false
	}

	dirfd := int64(int32(ev.Args[dirfdArgIndex]))
	if dirfd == unix.AT_FDCWD {
		return f.cwdForPID(ev.Pid)
	}

	path, ok := f.fdPath(ev.Pid, normalizeTrackedFD(ev.Args[dirfdArgIndex]))
	if !ok {
		return "", false
	}
	return path, true
}

func (f *pathFilter) stateForPID(pid uint32) *processPathState {
	if state := f.stateByPID[pid]; state != nil {
		return state
	}
	state := &processPathState{}
	f.stateByPID[pid] = state
	return state
}

func (f *pathFilter) stateForPIDIfPresent(pid uint32) *processPathState {
	return f.stateByPID[pid]
}

func (f *pathFilter) maybeDropPIDState(pid uint32) {
	state := f.stateByPID[pid]
	if state == nil {
		return
	}
	hasCWD := state.cwd != ""
	hasTrackedFDs := len(state.trackedFDs) > 0
	hasFDPaths := len(state.fdPaths) > 0
	if hasCWD || hasTrackedFDs || hasFDPaths {
		return
	}
	delete(f.stateByPID, pid)
}

func (f *pathFilter) trackFD(pid uint32, fd uint64) {
	state := f.stateForPID(pid)
	if state.trackedFDs == nil {
		state.trackedFDs = make(map[uint64]struct{})
	}
	state.trackedFDs[fd] = struct{}{}
}

func (f *pathFilter) untrackFD(pid uint32, fd uint64) {
	state := f.stateForPIDIfPresent(pid)
	if state == nil || state.trackedFDs == nil {
		return
	}
	delete(state.trackedFDs, fd)
	if len(state.trackedFDs) == 0 {
		state.trackedFDs = nil
	}
	f.maybeDropPIDState(pid)
}

func (f *pathFilter) fdTracked(pid uint32, fd uint64) bool {
	state := f.stateForPIDIfPresent(pid)
	if state == nil || state.trackedFDs == nil {
		return false
	}
	_, ok := state.trackedFDs[fd]
	return ok
}

func (f *pathFilter) setFDPath(pid uint32, fd uint64, path string) {
	state := f.stateForPID(pid)
	if state.fdPaths == nil {
		state.fdPaths = make(map[uint64]string)
	}
	state.fdPaths[fd] = path
}

func (f *pathFilter) syncTrackedFD(pid uint32, fd uint64, path string) {
	if _, matched := f.paths[path]; matched {
		f.trackFD(pid, fd)
		return
	}
	f.untrackFD(pid, fd)
}

func (f *pathFilter) unsetFDPath(pid uint32, fd uint64) {
	state := f.stateForPIDIfPresent(pid)
	if state == nil || state.fdPaths == nil {
		return
	}
	delete(state.fdPaths, fd)
	if len(state.fdPaths) == 0 {
		state.fdPaths = nil
	}
	f.maybeDropPIDState(pid)
}

func (f *pathFilter) fdPath(pid uint32, fd uint64) (string, bool) {
	state := f.stateForPIDIfPresent(pid)
	if state == nil || state.fdPaths == nil {
		return "", false
	}
	path, ok := state.fdPaths[fd]
	return path, ok
}

func (f *pathFilter) cwdForPID(pid uint32) (string, bool) {
	if state := f.stateForPIDIfPresent(pid); state != nil && state.cwd != "" {
		return state.cwd, true
	}

	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return "", false
	}
	cwd = filepath.Clean(cwd)
	f.stateForPID(pid).cwd = cwd
	return cwd, true
}

func (f *pathFilter) rewritePIDPaths(pid uint32, oldPath, newPath string) {
	state := f.stateForPIDIfPresent(pid)
	if state == nil {
		return
	}

	if state.cwd != "" {
		if rewritten, changed := rewritePathPrefix(state.cwd, oldPath, newPath); changed {
			state.cwd = rewritten
		}
	}

	if state.fdPaths == nil {
		return
	}
	for fd, path := range state.fdPaths {
		rewritten, changed := rewritePathPrefix(path, oldPath, newPath)
		if !changed {
			continue
		}
		state.fdPaths[fd] = rewritten
		f.syncTrackedFD(pid, fd, rewritten)
	}
}

func (f *pathFilter) dropPIDPaths(pid uint32, target string) {
	state := f.stateForPIDIfPresent(pid)
	if state == nil || state.fdPaths == nil {
		return
	}
	for fd, path := range state.fdPaths {
		if path != target {
			continue
		}
		f.untrackFD(pid, fd)
		delete(state.fdPaths, fd)
	}
	if len(state.fdPaths) == 0 {
		state.fdPaths = nil
	}
	f.maybeDropPIDState(pid)
}

func rewritePathPrefix(path, oldBase, newBase string) (string, bool) {
	path = filepath.Clean(path)
	oldBase = filepath.Clean(oldBase)
	newBase = filepath.Clean(newBase)

	if path == oldBase {
		return newBase, true
	}

	prefix := oldBase + string(os.PathSeparator)
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return path, false
	}
	return filepath.Join(newBase, path[len(prefix):]), true
}

func pathBaseFDArgIndex(syscallID int64, argIndex int) (int, bool) {
	switch syscallID {
	case int64(unix.SYS_OPENAT), int64(unix.SYS_OPENAT2), int64(unix.SYS_UNLINKAT), int64(unix.SYS_NEWFSTATAT), int64(unix.SYS_FACCESSAT), int64(unix.SYS_STATX), int64(unix.SYS_FACCESSAT2):
		if argIndex == 1 {
			return 0, true
		}
	case int64(unix.SYS_RENAMEAT), int64(unix.SYS_RENAMEAT2):
		switch argIndex {
		case 1:
			return 0, true
		case 3:
			return 2, true
		}
	case int64(unix.SYS_OPEN), int64(unix.SYS_ACCESS), int64(unix.SYS_STAT), int64(unix.SYS_LSTAT), int64(unix.SYS_CHDIR), int64(unix.SYS_UNLINK), int64(unix.SYS_RENAME):
		return -1, true
	}
	return -1, false
}

func normalizeTrackedFD(raw uint64) uint64 {
	return uint64(uint32(raw))
}
