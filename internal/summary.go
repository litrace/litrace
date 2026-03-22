// SPDX-License-Identifier: GPL-2.0-only

package trace

type syscallSummary struct {
	Calls   uint64
	Errors  uint64
	TotalNs uint64
}

func addSummaryEvent(summary map[int64]syscallSummary, ev Event) {
	stats := summary[ev.SyscallID]

	stats.Calls++
	if ev.Ret < 0 {
		stats.Errors++
	}
	stats.TotalNs += ev.Dur
	summary[ev.SyscallID] = stats
}
