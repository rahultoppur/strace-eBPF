from bcc import BPF

# Define our BPF source program
bpf_source = """
int hello(void *ctx)
{
    //bpf_trace_printk("Hello, world!\\n");
    bpf_trace_printk("\\n");
    return 0;      
}
"""

# Load BPF program
b = BPF(text=bpf_source)
#b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
