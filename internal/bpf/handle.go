package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type HandleConfig struct {
	FollowForks     bool
	TraceSyscallIDs map[int64]struct{}
}

type Handle struct {
	objs         tracerObjects
	objectsReady bool

	config HandleConfig

	tpEnter     link.Link
	tpExit      link.Link
	tpSchedExit link.Link

	reader *ringbuf.Reader
}

func NewHandle(targetTGIDs []uint32, cfg HandleConfig) (_ *Handle, err error) {
	handle := &Handle{config: normalizeHandleConfig(cfg)}
	defer func() {
		if err != nil {
			_ = handle.Close()
		}
	}()

	if err := applyConfig(&handle.objs, targetTGIDs, handle.config); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}
	handle.objectsReady = true

	handle.tpEnter, err = link.Tracepoint("raw_syscalls", "sys_enter", handle.objs.TraceSysEnter, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach sys_enter tracepoint: %w", err)
	}

	handle.tpExit, err = link.Tracepoint("raw_syscalls", "sys_exit", handle.objs.TraceSysExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach sys_exit tracepoint: %w", err)
	}

	handle.tpSchedExit, err = link.Tracepoint("sched", "sched_process_exit", handle.objs.TraceSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach sched_process_exit tracepoint: %w", err)
	}

	handle.reader, err = ringbuf.NewReader(handle.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open ring buffer reader: %w", err)
	}

	return handle, nil
}

func normalizeHandleConfig(cfg HandleConfig) HandleConfig {
	normalized := cfg
	normalized.TraceSyscallIDs = make(map[int64]struct{}, len(cfg.TraceSyscallIDs))
	for id := range cfg.TraceSyscallIDs {
		normalized.TraceSyscallIDs[id] = struct{}{}
	}
	return normalized
}

func applyConfig(objs *tracerObjects, targetTGIDs []uint32, cfg HandleConfig) error {
	spec, err := loadTracer()
	if err != nil {
		return err
	}

	followForks := uint8(0)
	if cfg.FollowForks {
		followForks = 1
	}

	followForksVar, ok := spec.Variables["follow_forks"]
	if !ok {
		return fmt.Errorf("missing runtime constant %q", "follow_forks")
	}
	if err := followForksVar.Set(followForks); err != nil {
		return fmt.Errorf("set runtime constant %q: %w", "follow_forks", err)
	}

	traceFilterEnabled := uint8(0)
	if len(cfg.TraceSyscallIDs) > 0 {
		traceFilterEnabled = 1
	}

	traceFilterVar, ok := spec.Variables["trace_filter_enabled"]
	if !ok {
		return fmt.Errorf("missing runtime constant %q", "trace_filter_enabled")
	}
	if err := traceFilterVar.Set(traceFilterEnabled); err != nil {
		return fmt.Errorf("set runtime constant %q: %w", "trace_filter_enabled", err)
	}

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return err
	}

	if traceFilterEnabled != 0 {
		for syscallID := range cfg.TraceSyscallIDs {
			if err := objs.TraceSyscallFilter.Put(uint32(syscallID), uint8(1)); err != nil {
				return fmt.Errorf("failed to populate trace syscall filter map: %w", err)
			}
		}
	}

	for _, tgid := range targetTGIDs {
		if err := objs.TargetPids.Put(tgid, uint8(1)); err != nil {
			return fmt.Errorf("failed to populate PID map: %w", err)
		}
	}

	return nil
}

func (h *Handle) ReadEvent() ([]byte, error) {
	record, err := h.reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func IsReaderClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed)
}

func (h *Handle) CloseReader() error {
	if h.reader == nil {
		return nil
	}
	err := h.reader.Close()
	if IsReaderClosed(err) {
		return nil
	}
	return err
}

func (h *Handle) Close() error {
	var closeErr error

	if err := h.CloseReader(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close ring buffer reader: %w", err))
	}
	if h.tpSchedExit != nil {
		if err := h.tpSchedExit.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sched_process_exit tracepoint: %w", err))
		}
	}
	if h.tpExit != nil {
		if err := h.tpExit.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sys_exit tracepoint: %w", err))
		}
	}
	if h.tpEnter != nil {
		if err := h.tpEnter.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sys_enter tracepoint: %w", err))
		}
	}
	if h.objectsReady {
		if err := h.objs.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close BPF objects: %w", err))
		}
	}

	return closeErr
}
