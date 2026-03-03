package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	f, err := os.CreateTemp("", "litrace-fd-scalar-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp file: %v\n", err)
		os.Exit(1)
	}

	path := f.Name()
	defer os.Remove(path)

	fd := int(f.Fd())
	if _, err := f.Seek(128, 0); err != nil {
		fmt.Fprintf(os.Stderr, "lseek failed: %v\n", err)
		os.Exit(1)
	}

	if err := unix.Fchmod(fd, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "fchmod failed: %v\n", err)
		os.Exit(1)
	}

	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close failed: %v\n", err)
		os.Exit(1)
	}
}
