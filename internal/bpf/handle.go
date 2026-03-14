package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Handle struct {
	objs         tracerObjects
	objectsReady bool

	tpEnter     link.Link
	tpExit      link.Link
	tpSchedExit link.Link

	reader *ringbuf.Reader
}

func NewHandle(tgid uint32, followForks bool) (_ *Handle, err error) {
	handle := &Handle{}
	defer func() {
		if err != nil {
			_ = handle.Close()
		}
	}()

	if err := loadTracerObjects(&handle.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}
	handle.objectsReady = true

	followForksVal := uint8(0)
	if followForks {
		followForksVal = 1
	}
	if err := handle.objs.FollowForksConfig.Put(uint32(0), followForksVal); err != nil {
		return nil, fmt.Errorf("failed to set follow-forks config: %w", err)
	}
	if err := handle.objs.TargetPids.Put(tgid, uint8(1)); err != nil {
		return nil, fmt.Errorf("failed to populate PID map: %w", err)
	}

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
