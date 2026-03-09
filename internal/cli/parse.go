package cli

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	FollowForks     bool
	TraceOutputPath string
	ProgramName     string
	ProgramPath     string
	ProgramArgs     []string
}

func usageError(exeName string) error {
	return fmt.Errorf("usage: %s [-f] [-o FILE] <program> [args...]", exeName)
}

func ParseArgs(exeName string, args []string) (Config, error) {
	cfg := Config{}

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

	args = fs.Args()

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
