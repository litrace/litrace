package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	trace "litrace/internal"
	"litrace/internal/cli"
)

func exitWithWaitStatus(ws syscall.WaitStatus) {
	if ws.Exited() {
		os.Exit(ws.ExitStatus())
	}

	if ws.Signaled() {
		sig := ws.Signal()
		signal.Reset(sig)
		_ = syscall.Kill(syscall.Getpid(), sig)
		os.Exit(128 + int(sig))
	}

	os.Exit(1)
}

func main() {
	exeName := os.Args[0]

	cfg, err := cli.ParseArgs(exeName, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	traceOutput := os.Stderr
	if cfg.TraceOutputPath != "" {
		file, err := os.Create(cfg.TraceOutputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, fmt.Errorf("failed to open trace output %s: %w", cfg.TraceOutputPath, err))
			os.Exit(1)
		}
		defer file.Close()
		traceOutput = file
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ws, err := trace.Run(trace.Config{
		ProgramName:     cfg.ProgramName,
		ProgramPath:     cfg.ProgramPath,
		ProgramArgs:     cfg.ProgramArgs,
		AttachPIDs:      cfg.AttachPIDs,
		FollowForks:     cfg.FollowForks,
		TraceSyscallIDs: cfg.TraceSyscallIDs,
		TracePaths:      cfg.TracePaths,
	}, trace.Options{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		TraceOutput: traceOutput,
		Signals:     sigCh,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", exeName, err)
		os.Exit(1)
	}

	exitWithWaitStatus(ws)
}
