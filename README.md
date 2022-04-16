# strace-eBPF

A simplified version of `strace` made using `eBPF`. 

## General Approach

`strace-eBPF` makes use of kernel tracepoints (specifically `sys_enter` and `sys_exit`) to trace the underlying syscalls made by a program. Currently, ~25 syscalls are supported, which means that the respective arguments present in each register are formatted. For the other syscalls that are made, the register contents are dumped and displayed as bytestrings. 

Return values are also traced for each syscall. Similar to that of `strace`, the return value is present after the `=` sign for each syscall.

This project is comprised of three main components:
(1) `strace.c` : Raw BPF program written in C that uses tracepoints to gather tracing information
(2) `tracepoint-raw.py` : Python wrapper that created the BPF program and prints output
(3) `my_strace` : Script that `forks` a parent and a child. Parent runs the tracer, while the child runs the tracee.

## Usage
```
./my_strace "cat hello"
```

Make sure that the command you pass in is quoted. You need to run this command as root.

## Dependencies
`strace-eBPF` is written using Python and bcc (BPF compiler collection). Installation pre-requisites can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md). Supporting documentation for bcc can be found [here](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md).

eBPF is extremely kernel-specific. Especially for bcc, some features are available in specific kernel versions, while others are not. This implementation of `strace` was tested on `Ubuntu 20.04.3`, with the kernel version: `5.4.0-107-generic`.


