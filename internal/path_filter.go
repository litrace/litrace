package trace

import "golang.org/x/sys/unix"

type pathFilter struct {
	paths          map[string]struct{}
	trackedFDs     map[uint32]map[uint64]struct{}
	userTraceIDs   map[int64]struct{}
	userTraceAll   bool
	pathFilterMode bool
}

func newPathFilter(cfg Config) *pathFilter {
	filter := &pathFilter{
		paths:          make(map[string]struct{}, len(cfg.TracePaths)),
		trackedFDs:     make(map[uint32]map[uint64]struct{}),
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

	ids := make(map[int64]struct{}, len(cfg.TraceSyscallIDs)+7)
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
	case int64(unix.SYS_DUP):
		f.observeDupRet(ev, 0)
	case int64(unix.SYS_DUP2), int64(unix.SYS_DUP3):
		f.observeDupPair(ev)
	case int64(unix.SYS_FCNTL):
		f.observeFcntl(ev)
	case int64(unix.SYS_CLOSE):
		f.observeClose(ev)
	}
}

func (f *pathFilter) observeOpen(ev Event, pathArgIndex int) {
	if ev.Ret < 0 || !f.matchesPathAt(ev, pathArgIndex) {
		return
	}
	f.trackFD(ev.Pid, uint64(ev.Ret))
}

func (f *pathFilter) observeDupRet(ev Event, srcIndex int) {
	if ev.Ret < 0 || !f.argTracked(ev, srcIndex) {
		return
	}
	f.trackFD(ev.Pid, uint64(ev.Ret))
}

func (f *pathFilter) observeDupPair(ev Event) {
	if ev.ArgCount < 2 || ev.Ret < 0 {
		return
	}

	oldfd := ev.Args[0]
	newfd := ev.Args[1]
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

	f.trackFD(ev.Pid, uint64(ev.Ret))
}

func (f *pathFilter) observeClose(ev Event) {
	if ev.Ret < 0 || ev.ArgCount < 1 {
		return
	}
	f.untrackFD(ev.Pid, ev.Args[0])
}

func (f *pathFilter) hasTrackedFDArg(ev Event) bool {
	for i := 0; i < int(ev.ArgCount) && i < len(ev.ArgTypes); i++ {
		if ev.ArgTypes[i] != argFD {
			continue
		}
		if f.fdTracked(ev.Pid, ev.Args[i]) {
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
	return f.fdTracked(ev.Pid, ev.Args[idx])
}

func (f *pathFilter) matchesPath(ev Event) bool {
	switch ev.SyscallID {
	case int64(unix.SYS_OPEN):
		return f.matchesPathAt(ev, 0)
	case int64(unix.SYS_OPENAT):
		return f.matchesPathAt(ev, 1)
	default:
		return false
	}
}

func (f *pathFilter) matchesPathAt(ev Event, argIndex int) bool {
	path, ok := eventTracePathAt(ev, argIndex)
	if !ok {
		return false
	}
	_, ok = f.paths[path]
	return ok
}

func (f *pathFilter) trackFD(pid uint32, fd uint64) {
	if fdSet := f.trackedFDs[pid]; fdSet != nil {
		fdSet[fd] = struct{}{}
		return
	}
	f.trackedFDs[pid] = map[uint64]struct{}{fd: {}}
}

func (f *pathFilter) untrackFD(pid uint32, fd uint64) {
	fdSet := f.trackedFDs[pid]
	if fdSet == nil {
		return
	}
	delete(fdSet, fd)
	if len(fdSet) == 0 {
		delete(f.trackedFDs, pid)
	}
}

func (f *pathFilter) fdTracked(pid uint32, fd uint64) bool {
	fdSet := f.trackedFDs[pid]
	if fdSet == nil {
		return false
	}
	_, ok := fdSet[fd]
	return ok
}
