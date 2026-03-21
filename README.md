# Litrace - A Lightweight Linux Syscall Tracer

Litrace (pronounced "light rays") is a Linux system call tracer inspired by [strace](https://strace.io/). Powered
by [eBPF](https://ebpf.io/), Litrace aims to provide the same level of visibility as strace, but with significantly
lower runtime [overhead](#Overhead).

Litrace is written in Go and builds into a single statically linked binary with no runtime dependencies, making it easy
to deploy.

## Some Features

### Attach to an already running process

```bash
$ litrace -o lt -p 109893
litrace: Process 109893 attached
```

### Filter by syscall name

```bash
$ litrace -e trace=access,openat /bin/true
access("/etc/ld.so.preload", 004) = -1 ENOENT (no such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
+++ exited with 0 +++
```

### Trace only syscalls accessing a given path

```bash
$ litrace -P /etc/ld.so.cache ls /var > /dev/null
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=131471, ...}) = 0
mmap(NULL, 131471, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f93411af000
close(3) = 0
+++ exited with 0 +++
```

### Dump data read from/written to file descriptors.

```bash
litrace -e trace=write /bin/echo hello > /dev/null
write(1, "hello\n", 6) = 6
+++ exited with 0 +++
```

### Count time, calls, and errors for each syscall

```bash
$ litrace -c ls > /dev/null
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.01    0.000396          11        35         0 mmap
 23.17    0.000229           6        35        13 openat
  6.83    0.000068           2        23         0 fstat
  6.22    0.000062           2        24         0 close
  5.52    0.000055           9         6         0 mprotect
  4.85    0.000048           5         8         0 read
  2.03    0.000020          20         1         0 munmap
  2.02    0.000020           6         3         0 brk
  2.01    0.000020           9         2         2 statfs
  1.53    0.000015           7         2         0 getdents64
  1.31    0.000013           6         2         2 access
  1.11    0.000011           1         6         4 prctl
  0.67    0.000007           3         2         0 pread64
  0.44    0.000004           2         2         2 ioctl
  0.39    0.000004           3         1         0 getrandom
  0.34    0.000003           3         1         0 arch_prctl
  0.29    0.000003           2         1         0 futex
  0.29    0.000003           2         1         0 prlimit64
  0.24    0.000002           2         1         0 rseq
  0.24    0.000002           2         1         0 set_robust_list
  0.24    0.000002           2         1         0 set_tid_address
  0.23    0.000002           2         1         0 write
------ ----------- ----------- --------- --------- ----------------
100.00    0.000989           6       159        23 total
```

## Overhead

As [Brendan Gregg](https://www.brendangregg.com/blog/2014-05-12/strace-wow-much-syscall.html) notes, *"The performance
overhead of strace is relative to the system call rate it is instrumenting."*

Using his simple worst-case test:

```bash
dd if=/dev/zero of=/dev/null bs=1 count=500k
512000+0 records in
512000+0 records out
512000 bytes (512 kB, 500 KiB) copied, 0.508616 s, 1.0 MB/s
```

With strace, tracing a syscall that is never called, accept(), nevertheless leads to overhead:

```bash
strace -eaccept dd if=/dev/zero of=/dev/null bs=1 count=500k
512000+0 records in
512000+0 records out
512000 bytes (512 kB, 500 KiB) copied, 35.9803 s, 14.2 kB/s
+++ exited with 0 +++
```

That is **~70x slower** than baseline.

Now the same test with Litrace:

```bash
litrace -e trace=accept dd if=/dev/zero of=/dev/null bs=1 count=500k
512000+0 records in
512000+0 records out
512000 bytes (512 kB, 500 KiB) copied, 1.22717 s, 417 kB/s
+++ exited with 0 +++
```

That is **~2.4x slower** than baseline, but **~29x faster** than strace.

`perf trace` has comparable overhead to Litrace, but its filtering and decoding are more limited than strace.

```bash
perf trace -eaccept dd if=/dev/zero of=/dev/null bs=1 count=500k
512000+0 records in
512000+0 records out
512000 bytes (512 kB, 500 KiB) copied, 1.26824 s, 404 kB/s
```
