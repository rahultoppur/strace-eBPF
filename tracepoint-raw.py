#!/usr/bin/env python3

from bcc import BPF
from bcc.syscall import syscalls, syscall_name
import time
import argparse
import sys
import os
from ctypes import *
import socket, struct

BPF_SRC = "strace.c"
BPF_SRC_EDITED = "strace_edited.c"

parser = argparse.ArgumentParser(
    description="A version of strace using eBPF")

parser.add_argument("-p", "--pid", help="trace this PID only", required=True)
args = parser.parse_args()


# Read PID from command line, setup PID filter
if args.pid:
    with open(BPF_SRC) as f:
        new_text = f.read().replace("PID_FILTER_BEGIN", f"if (pid == {args.pid} || ppid == {args.pid}) {{").replace("PID_FILTER_END", f"}}")
    with open(BPF_SRC_EDITED, "w") as f:
        f.write(new_text)

b = BPF(src_file=BPF_SRC_EDITED)

# Print header
print("COMM", "PID", "SYSCALL_ID", "ARGS[0]", "ARGS[1]", "ARGS[2]", "ARGS[3]", "ARGS[4]", "ARGS[5]")

def print_event(cpu, data, size):
    event = b["events"].event(data)

    # Map each syscall to its corresponding format string
    print_format = { 
            0   : f"(FD: {event.fd} | BUF: {event.argv0}... | COUNT: {event.count})",
            1   : f"(FD: {event.fd} | BUF: {event.argv0}... | COUNT: {event.count})",
            2   : f"(FILENAME: {event.argv0} | FLAGS: {event.flags} | MODE: {event.mode})",
            3   : f"(FD: {event.fd})",
            42  : f"(IP: {socket.inet_ntoa(struct.pack('<L', event.s_addr))} | PORT: {event.port})",
            59  : f"(FD: {event.df} | FILENAME: {event.filename} | ARGV0: {event.argv0} | ARGV1: {event.argv1} | ARGV2: {event.argv2} | ARGV3: {event.argv3} |)",
            62  : f"(PID: {event.pid} | SIGNAL: {event.sigal})",
            257 : f"(FILENAME: {event.argv0} | FLAGS: {event.flags} | MODE: {event.mode})" }


    sys_name = syscall_name(event.syscall_id).decode('utf-8')
    try:
        syscall_args = print_format[event.syscall_id]
        print(f"{sys_name}{syscall_args}")
    except:
        # Syscall not yet supported--just print out it's name for now
        print(f"{sys_name}(...)")
        pass

    # If we see syscall ID 231 (exit_group), log the entry and stop tracing
    if event.syscall_id == 231 and event.comm == b"python3":
        print("exit_groups() received", "*" * 40)
        os._exit(0)


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break