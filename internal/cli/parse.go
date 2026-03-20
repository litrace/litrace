package cli

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"litrace/internal/syscalls"

	"github.com/spf13/pflag"
)

type Config struct {
	FollowForks     bool
	TraceOutputPath string
	TraceSyscallIDs map[int64]struct{}
	AttachPIDs      []int
	ProgramName     string
	ProgramPath     string
	ProgramArgs     []string
}

func usageError(exeName string) error {
	return fmt.Errorf("usage: %s [-f] [-o FILE] [-p PID[,PID...]] <program> [args...]", exeName)
}

func ParseArgs(exeName string, args []string) (Config, error) {
	cfg := Config{TraceSyscallIDs: make(map[int64]struct{})}
	var traceExpressions []string
	var attachExpressions []string

	for _, arg := range args {
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			break
		}
		if strings.HasPrefix(arg, "--") {
			name := strings.SplitN(arg, "=", 2)[0]
			return Config{}, fmt.Errorf("unknown option %q", name)
		}
	}

	fs := pflag.NewFlagSet(exeName, pflag.ContinueOnError)
	fs.SetInterspersed(false)
	fs.SetOutput(io.Discard)
	fs.BoolVarP(&cfg.FollowForks, "follow-forks", "f", false, "follow child processes created via fork/clone")
	fs.StringVarP(&cfg.TraceOutputPath, "output", "o", "", "write trace output to FILE")
	fs.StringArrayVarP(&attachExpressions, "attach", "p", nil, "trace existing processes by PID")
	fs.StringArrayVarP(&traceExpressions, "trace", "e", nil, "trace only specified syscall names")

	if err := fs.Parse(args); err != nil {
		var notExistErr *pflag.NotExistError
		if errors.As(err, &notExistErr) {
			name := notExistErr.GetSpecifiedName()
			short := notExistErr.GetSpecifiedShortnames()
			for _, arg := range args {
				if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
					break
				}
				if short != "" {
					if arg == "-"+short || strings.HasPrefix(arg, "-"+short+"=") {
						return Config{}, fmt.Errorf("unknown option %q", "-"+short)
					}
				}
				if name != "" {
					if arg == "-"+name || strings.HasPrefix(arg, "-"+name+"=") {
						return Config{}, fmt.Errorf("unknown option %q", "-"+name)
					}
					if arg == "--"+name || strings.HasPrefix(arg, "--"+name+"=") {
						return Config{}, fmt.Errorf("unknown option %q", "--"+name)
					}
				}
			}
			if name != "" {
				return Config{}, fmt.Errorf("unknown option %q", "--"+name)
			}
			if short != "" {
				return Config{}, fmt.Errorf("unknown option %q", "-"+short)
			}
		}
		return Config{}, err
	}

	ids, err := parseTraceExpressions(traceExpressions)
	if err != nil {
		return Config{}, err
	}
	cfg.TraceSyscallIDs = ids

	attachPIDs, err := parseAttachExpressions(attachExpressions)
	if err != nil {
		return Config{}, err
	}
	cfg.AttachPIDs = attachPIDs

	args = fs.Args()

	if len(cfg.AttachPIDs) > 0 {
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

	cfg.ProgramName = args[0]
	cfg.ProgramPath = path
	cfg.ProgramArgs = args[1:]
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

func parseTraceExpressions(expressions []string) (map[int64]struct{}, error) {
	ids := make(map[int64]struct{})
	if len(expressions) == 0 {
		return ids, nil
	}

	for _, expression := range expressions {
		if !strings.HasPrefix(expression, "trace=") {
			return nil, fmt.Errorf("invalid -e expression %q: expected trace=<syscall[,syscall...]>", expression)
		}

		selector := strings.TrimPrefix(expression, "trace=")
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
