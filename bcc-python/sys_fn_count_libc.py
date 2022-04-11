from bcc import BPF
from time import sleep

# One alternative is just to loop through
# all the syscalls and generate a large
# bpf_source file. Then parameterize the
# resulting function calls for each 
# registered kprobe.

bpf_source = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char args[64];
};

BPF_PERF_OUTPUT(events);

// Create a hashmap called 'counts' 

int count(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    
    bpf_probe_read(&data.args, sizeof(data.args), (void *)PT_REGS_PARM2(ctx));
    events.perf_submit(ctx, &data, sizeof(data));    
 
    return 0; 
}
"""

# Generate bpf source for each syscall we want to track
def gen_bpf_source(syscalls):
    source = """
    #include <uapi/linux/ptrace.h>

    struct data_t {
        u32 pid;
        char args[64];
    };

    BPF_PERF_OUTPUT(events);

    // Create a hashmap called 'counts' 
    BPF_HASH(counts);
    """
    for k, v in syscalls.items():
        s_source = bpf_source 
        s_source = s_source.replace('SYSCALL_NAME', str(v))
        s_source = s_source.replace('SYSCALL_NUMBER', str(k))
        source += s_source 

    return source

# map syscall numbers to syscalls
syscalls = {
    162 : "sys_sync" ,
    60  : "sys_exit",
    56  : "sys_clone"
}

# Define our BPF program
#b = BPF(text=gen_bpf_source(syscalls))

b = BPF(text=bpf_source)

# Attach our kprobes 
for k, v in syscalls.items():
    #b.attach_kprobe(event=b.get_syscall_fnname(v.split('_')[-1]), fn_name="count_fn_"+v)
    b.attach_uprobe(name="c", sym="strncpy", fn_name="count")

# header
#print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# define callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    #print("%10d \"%s\"" % (event.pid, event.args.decode('ascii')))
    print(f"PID: {event.pid}\nARGS: {event.args.decode()}")

b["events"].open_perf_buffer(print_event)

# format output
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
