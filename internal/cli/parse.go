// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	trace "litrace/internal"
	"litrace/internal/syscalls"

	"github.com/spf13/pflag"
)

type Config struct {
	TraceOutputPath string
	Trace           trace.Config
}

type parsedFlags struct {
	traceExpressions  []string
	traceSelectors    []string
	attachExpressions []string
	tracePaths        []string
}

type appendStringValue struct {
	values *[]string
}

func newAppendStringValue(values *[]string) *appendStringValue {
	return &appendStringValue{values: values}
}

func (v *appendStringValue) String() string {
	if v == nil || v.values == nil {
		return ""
	}
	return strings.Join(*v.values, ",")
}

func (v *appendStringValue) Set(value string) error {
	*v.values = append(*v.values, value)
	return nil
}

func (v *appendStringValue) Type() string {
	return "string"
}

func usageError(exeName string) error {
	return fmt.Errorf("usage: %s [-f] [-c] [-o FILE] [-p PID[,PID...]] [-P PATH] <program> [args...]", exeName)
}

func newFlagSet(exeName string, cfg *Config, flags *parsedFlags) *pflag.FlagSet {
	fs := pflag.NewFlagSet(exeName, pflag.ContinueOnError)
	fs.SetInterspersed(false)
	fs.SetOutput(io.Discard)
	fs.BoolVarP(&cfg.Trace.FollowForks, "follow-forks", "f", false, "follow child processes created via fork/clone")
	fs.BoolVarP(&cfg.Trace.SummaryOnly, "summary-only", "c", false, "print aggregate syscall summary instead of per-syscall lines")
	fs.StringVarP(&cfg.TraceOutputPath, "output", "o", "", "write trace output to FILE")
	fs.StringArrayVarP(&flags.attachExpressions, "attach", "p", nil, "trace existing processes by PID")
	fs.StringArrayVarP(&flags.tracePaths, "trace-path", "P", nil, "trace only syscalls accessing PATH")
	fs.VarP(newAppendStringValue(&flags.traceExpressions), "trace-expression", "e", "trace only specified syscall names")
	fs.Var(newAppendStringValue(&flags.traceSelectors), "trace", "trace only specified syscall names")
	_ = fs.MarkHidden("trace-expression")
	return fs
}

func normalizeFlagParseError(err error) error {
	var notExistErr *pflag.NotExistError
	if errors.As(err, &notExistErr) {
		if short := notExistErr.GetSpecifiedShortnames(); short != "" {
			return fmt.Errorf("unknown option %q", "-"+short)
		}
		if name := notExistErr.GetSpecifiedName(); name != "" {
			return fmt.Errorf("unknown option %q", "--"+name)
		}
	}
	return err

}

func parseTraceIDs(expressions []string, selectors []string) (map[int64]struct{}, error) {
	ids, err := parseTraceExpressions(expressions)
	if err != nil {
		return nil, err
	}

	selectorIDs, err := parseTraceSelectors(selectors)
	if err != nil {
		return nil, err
	}
	for id := range selectorIDs {
		ids[id] = struct{}{}
	}
	return ids, nil
}

func ParseArgs(exeName string, args []string) (Config, error) {
	cfg := Config{
		Trace: trace.Config{
			TraceSyscallIDs: make(map[int64]struct{}),
		},
	}
	var flags parsedFlags

	fs := newFlagSet(exeName, &cfg, &flags)
	if err := fs.Parse(args); err != nil {
		return Config{}, normalizeFlagParseError(err)
	}

	ids, err := parseTraceIDs(flags.traceExpressions, flags.traceSelectors)
	if err != nil {
		return Config{}, err
	}
	cfg.Trace.TraceSyscallIDs = ids

	attachPIDs, err := parseAttachExpressions(flags.attachExpressions)
	if err != nil {
		return Config{}, err
	}
	cfg.Trace.AttachPIDs = attachPIDs

	normalizedTracePaths, err := parseTracePaths(flags.tracePaths)
	if err != nil {
		return Config{}, err
	}
	cfg.Trace.TracePaths = normalizedTracePaths

	args = fs.Args()

	if len(cfg.Trace.AttachPIDs) > 0 {
		if len(args) != 0 {
			return Config{}, fmt.Errorf("cannot use -p with a program")
		}
		return cfg, nil
	}

	if len(args) == 0 {
		return Config{}, usageError(exeName)
	}

	path, err := exec.LookPath(args[0])
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", args[0], err)
	}

	cfg.Trace.ProgramName = args[0]
	cfg.Trace.ProgramPath = path
	cfg.Trace.ProgramArgs = args[1:]
	return cfg, nil
}

func parseAttachExpressions(expressions []string) ([]int, error) {
	if len(expressions) == 0 {
		return nil, nil
	}

	seen := make(map[int]struct{})
	pids := make([]int, 0)
	for _, expression := range expressions {
		if expression == "" {
			return nil, fmt.Errorf("invalid -p expression %q: empty PID list", expression)
		}

		for _, token := range strings.Split(expression, ",") {
			if token == "" {
				return nil, fmt.Errorf("invalid -p expression %q: empty PID", expression)
			}

			pid, err := strconv.Atoi(token)
			if err != nil || pid <= 0 {
				return nil, fmt.Errorf("invalid -p PID %q", token)
			}
			if _, ok := seen[pid]; ok {
				continue
			}
			seen[pid] = struct{}{}
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

func parseTracePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("invalid -P path %q: empty path", path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("normalize -P path %q: %w", path, err)
		}
		normalized = append(normalized, filepath.Clean(abs))
	}

	return normalized, nil
}

func parseTraceExpressions(expressions []string) (map[int64]struct{}, error) {
	ids := make(map[int64]struct{})
	if len(expressions) == 0 {
		return ids, nil
	}

	for _, expression := range expressions {
		selector := expression
		if strings.HasPrefix(expression, "trace=") {
			selector = strings.TrimPrefix(expression, "trace=")
		} else if strings.Contains(expression, "=") {
			return nil, fmt.Errorf("invalid -e expression %q: expected trace=<syscall[,syscall...]>", expression)
		}
		if selector == "" {
			return nil, fmt.Errorf("invalid -e expression %q: empty trace selector", expression)
		}

		for _, syscallName := range strings.Split(selector, ",") {
			if syscallName == "" {
				return nil, fmt.Errorf("invalid -e expression %q: empty syscall name", expression)
			}
			syscallID, ok := syscalls.ID(syscallName)
			if !ok {
				return nil, fmt.Errorf("unknown syscall %q in -e trace selector", syscallName)
			}
			ids[syscallID] = struct{}{}
		}
	}

	return ids, nil
}

func parseTraceSelectors(selectors []string) (map[int64]struct{}, error) {
	ids := make(map[int64]struct{})
	if len(selectors) == 0 {
		return ids, nil
	}

	for _, selector := range selectors {
		if selector == "" {
			return nil, fmt.Errorf("invalid --trace selector %q: empty trace selector", selector)
		}

		for _, syscallName := range strings.Split(selector, ",") {
			if syscallName == "" {
				return nil, fmt.Errorf("invalid --trace selector %q: empty syscall name", selector)
			}
			syscallID, ok := syscalls.ID(syscallName)
			if !ok {
				return nil, fmt.Errorf("unknown syscall %q in --trace selector", syscallName)
			}
			ids[syscallID] = struct{}{}
		}
	}

	return ids, nil
}
