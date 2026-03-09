module litrace

go 1.25.5

require (
	github.com/cilium/ebpf v0.20.0
	golang.org/x/sys v0.37.0
)

require github.com/spf13/pflag v1.0.10

tool github.com/cilium/ebpf/cmd/bpf2go
