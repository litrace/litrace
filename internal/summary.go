package trace

type syscallSummary struct {
	Calls   uint64
	Errors  uint64
	TotalNs uint64
}

func addSummaryEvent(summary map[int64]*syscallSummary, ev Event) {
	stats := summary[ev.SyscallID]
	if stats == nil {
		stats = &syscallSummary{}
		summary[ev.SyscallID] = stats
	}

	stats.Calls++
	if ev.Ret < 0 {
		stats.Errors++
	}
	stats.TotalNs += ev.Dur
}
