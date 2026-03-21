# Installation

## Pre-built Binary

Download the latest release from:

https://github.com/litrace/litrace/releases

## Building From Source

To build from source, install the following dependencies:

- `go`
- `make`
- `clang`
- `llvm`
- Linux kernel headers
- `libbpf` headers

Then run:

```sh
make
```

This will generate the `litrace` binary.
