// SPDX-License-Identifier: GPL-2.0-only

package trace

import (
	"fmt"
	"sort"
	"strings"

	"litrace/internal/syscalls"
)

type SummaryRow struct {
	Syscall string
	Calls   uint64
	Errors  uint64
	TotalNs uint64
}

func FormatSummary(summary map[int64]syscallSummary) string {
	rows := make([]SummaryRow, 0, len(summary))
	var totalCalls uint64
	var totalErrors uint64
	var totalNs uint64

	for syscallID, stats := range summary {
		rows = append(rows, SummaryRow{
			Syscall: syscalls.Name(syscallID),
			Calls:   stats.Calls,
			Errors:  stats.Errors,
			TotalNs: stats.TotalNs,
		})
		totalCalls += stats.Calls
		totalErrors += stats.Errors
		totalNs += stats.TotalNs
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalNs != rows[j].TotalNs {
			return rows[i].TotalNs > rows[j].TotalNs
		}
		return rows[i].Syscall < rows[j].Syscall
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%% time     seconds  usecs/call     calls    errors syscall\n")
	fmt.Fprintf(&b, "------ ----------- ----------- --------- --------- ----------------\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%6.2f %11.6f %11d %9d %9d %s\n",
			summaryPercent(row.TotalNs, totalNs),
			float64(row.TotalNs)/1e9,
			summaryUsecsPerCall(row.TotalNs, row.Calls),
			row.Calls,
			row.Errors,
			row.Syscall,
		)
	}
	fmt.Fprintf(&b, "------ ----------- ----------- --------- --------- ----------------\n")
	fmt.Fprintf(&b, "%6.2f %11.6f %11d %9d %9d total\n",
		summaryPercent(totalNs, totalNs),
		float64(totalNs)/1e9,
		summaryUsecsPerCall(totalNs, totalCalls),
		totalCalls,
		totalErrors,
	)

	return b.String()
}

func summaryPercent(totalNs, allNs uint64) float64 {
	if allNs == 0 {
		return 0
	}
	return (float64(totalNs) * 100) / float64(allNs)
}

func summaryUsecsPerCall(totalNs, calls uint64) uint64 {
	if calls == 0 {
		return 0
	}
	return totalNs / 1000 / calls
}
