# strace-eBPF

A simplified version of `strace` made using `eBPF`. 

## General Approach

`strace-eBPF` makes use of kernel tracepoints (specifically `sys_enter` and `sys_exit`) to trace the underlying syscalls made by a program. Currently, ~25 syscalls are supported, which means that the respective arguments present in each register are formatted. For the other syscalls that are made, the register contents are dumped and displayed as bytestrings. 

Return values are also traced for each syscall. Similar to that of `strace`, the return value is present after the `=` sign for each syscall.

This project is comprised of three main components:

1. `strace.c`: Raw BPF program written in C that uses tracepoints to gather tracing information
2. `tracepoint-raw`: Python wrapper that creates the BPF program and prints output
3. `my_strace`: Small script that `forks`. The parent runs the tracer (2), while the child runs the tracee (the program getting traced).

## Usage
```
./my_strace "cat hello"
```

Make sure that the command you pass in is quoted. You need to run this command as root.

## Dependencies
`strace-eBPF` is written using Python and bcc (BPF compiler collection). Installation pre-requisites can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md). Supporting documentation for bcc can be found [here](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md).

eBPF is extremely kernel-specific. Especially for bcc, some features are available in specific kernel versions, while others are not. This implementation of `strace-eBPF` was tested on `Ubuntu 20.04.3`, with the kernel version: `5.4.0-107-generic`.

## Sample Output
Below is a snippet of running the following command:
```
./my_strace "cat tmp/hello.txt"
```
```
Parent PID: 218879, Child PID: 218881
Beginning tracing...
b'python3' | pipe2(b'p5\xb1' | b'' | b'' | b'f\x0f\xef\xc0f\x0fo\x17f\x0fo\x0ef\x0ft\xc1f\x0fs\xfa')=0
b'python3' | clone(b'' | b'' | b'' | b'\x01W\x03')=218884
b'python3' | close(FD: 4)=0
b'python3' | read(FD: 3 | BUF: b''... | COUNT: 50000)=0
b'python3' | close(FD: 3)=0
b'python3' | clone(b'' | b'' | b'' | b'\x01W\x03')=0
b'python3' | set_robust_list(b' *(,\xc6\x7f' | b'' | b'' | b'\x04W\x03')=0
b'python3' | close(FD: 3)=0
b'python3' | rt_sigaction(b'' | b'' | b'@P\xc1+\xc6\x7f' | b'')=0
b'python3' | rt_sigaction(b'' | b'' | b'\xc0\x10I,\xc6\x7f' | b'')=0
b'python3' | openat(FD: -100 | FILENAME: b'' | FLAGS: 524288 | MODE: 0)=3
hello there!
b'python3' | getdents64(FD: 3 | FILE INFO: [d_name=b'', d_ino=1, d_type=0, d_reclen=1...])=168
b'python3' | getdents64(FD: 3 | FILE INFO: [d_name=b'.', d_ino=2144395, d_type=4, d_reclen=24...])=0
b'python3' | close(FD: 3)=0
b'python3' | execve(FD: 0 | FILENAME: b'/usr/local/sbin/' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=-2
b'python3' | execve(FD: 0 | FILENAME: b'/usr/local/bin/c' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=-2
b'python3' | execve(FD: 0 | FILENAME: b'/usr/sbin/cat' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=-2
b'python3' | execve(FD: 0 | FILENAME: b'/usr/bin/cat' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=-2
b'python3' | execve(FD: 0 | FILENAME: b'/sbin/cat' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=-2
b'python3' | execve(FD: 0 | FILENAME: b'/bin/cat' | ARGV0: b'cat' | ARGV1: b'tmp/hello.txt' | ARGV2: b'' | ARGV3: b'' |)=0
b'cat' | brk(ADDR: 0x0)=0x561480167000
b'cat' | arch_prctl(b'' | b'' | b'\xf3\x0f\x1e\xfaH\x8b\x07f\x818ont2\x818off' | b'\x02\x87\xff\xff\xf9\x86\xff\xff-\x87\xff\xff\xf9\x86\xff\xff\x02\x87\xff\xff')=-22
b'cat' | access(FILENAME: b'/etc/ld.so.prelo' | MODE: 4)=-2
b'cat' | openat(FD: -100 | FILENAME: b'/etc/ld.so.cache' | FLAGS: 524288 | MODE: 0)=3
b'cat' | fstat(FD: 3)=0
b'cat' | mmap(ADDR: 0x0 | FD: 3)=0x7f35b2a7c000
b'cat' | close(FD: 3)=0
b'cat' | openat(FD: -100 | FILENAME: b'/lib/x86_64-linux-gnu/libc.so.6' | FLAGS: 524288 | MODE: 0)=3
b'cat' | read(FD: 3 | BUF: b''... | COUNT: 832)=832
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 784)=784
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 32)=32
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 68)=68
b'cat' | fstat(FD: 3)=0
b'cat' | mmap(ADDR: 0x0 | FD: -1)=0x7f35b2a7a000
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 784)=784
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 32)=32
b'cat' | pread(FD: 3 | BUF: b'' | COUNT: 68)=68
b'cat' | mmap(ADDR: 0x0 | FD: 3)=0x7f35b2888000
b'cat' | mmap(ADDR: 0x7f35b28aa000 | FD: 3)=0x7f35b28aa000
b'cat' | mmap(ADDR: 0x7f35b2a22000 | FD: 3)=0x7f35b2a22000
b'cat' | mmap(ADDR: 0x7f35b2a70000 | FD: 3)=0x7f35b2a70000
b'cat' | mmap(ADDR: 0x7f35b2a76000 | FD: -1)=0x7f35b2a76000
b'cat' | close(FD: 3)=0
b'cat' | arch_prctl(b'' | b'\x80\xb5\xa7\xb25\x7f' | b'' | b'')=0
b'cat' | mprotect(b'_\x04' | b'' | b'' | b'(B^\xa0\xff\x7f')=0
b'cat' | mprotect(b'\x1c' | b'' | b'' | b'\xf0\xff\xffo')=0
b'cat' | mprotect(b'' | b'' | b'' | b'\xf0\xff\xffo')=0
b'cat' | munmap(b'glibc-ld.so.cache1.1_\x05' | b'' | b'' | b'\xf0\xff\xffo')=0
b'cat' | brk(ADDR: 0x0)=0x561480167000
b'cat' | brk(ADDR: 0x561480188000)=0x561480188000
b'cat' | openat(FD: -100 | FILENAME: b'/usr/lib/locale/locale-archive' | FLAGS: 524288 | MODE: 0)=3
b'cat' | fstat(FD: 3)=0
b'cat' | mmap(ADDR: 0x0 | FD: 3)=0x7f35b2318000
b'cat' | close(FD: 3)=0
b'cat' | fstat(FD: 1)=0
b'cat' | openat(FD: -100 | FILENAME: b'tmp/hello.txt' | FLAGS: 0 | MODE: 0)=3
b'cat' | fstat(FD: 3)=0
b'cat' | fadvise64(b'' | b'' | b'' | b'')=0
b'cat' | mmap(ADDR: 0x0 | FD: -1)=0x7f35b22f6000
b'cat' | read(FD: 3 | BUF: b''... | COUNT: 131072)=13
b'cat' | write(FD: 1 | BUF: b'hello there!\n'... | COUNT: 13)=13
b'cat' | read(FD: 3 | BUF: b'hello there!\n'... | COUNT: 131072)=0
b'cat' | munmap(b'' | b'' | b'' | b'')=0
b'cat' | close(FD: 3)=0
b'cat' | close(FD: 1)=0
b'cat' | close(FD: 2)=0
b'cat' | exit_group(ERRORCODE: 0)=0
exit_group() received, stopping trace... ****************************************
```
