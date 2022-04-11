from bcc import BPF
from time import sleep

# One alternative is just to loop through
# all the syscalls and generate a large
# bpf_source file. Then parameterize the
# resulting function calls for each 
# registered kprobe.

bpf_source = r"""

//int count_fn_SYSCALL_NAME(struct pt_regs *ctx, const char __user *filename)
//int sys_open(struct pt_regs *ctx, const char __user *filename)
int trace_sys_kill(void *ctx)
{
    //u64 value = 0;
    //u64 key = SYSCALL_NUMBER;

    /*
    u64 *p = counts.lookup(&key);
    if (p != 0) 
    {
        value = *p;
    }
    value++;
    counts.update(&key, &value);
    */

    struct data_t data = {};
    //data.pid = bpf_get_current_pid_tgid();
    //data.pid = pid;
    //data.signal = sig;
    strcpy(data.command, bpf_get_current_comm(&data.command, sizeof(data.command)));
   
    //bpf_trace_printk("filename is: %s\n", filename); 
    //strcpy(data.args, filename);
    
    //bpf_probe_read(&data.args, sizeof(data.args), (void *)PT_REGS_PARM1(ctx));
    events.perf_submit(ctx, &data, sizeof(data));    
 
    return 0; 
}
"""

# Generate bpf source for each syscall we want to track
def gen_bpf_source(syscalls):
    source = r"""
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    int signal;
    char command[64];
};

BPF_PERF_OUTPUT(events);

// Create a hashmap called 'counts' 
//BPF_HASH(counts);
"""
    for k, v in syscalls.items():
        s_source = bpf_source 
        s_source = s_source.replace('SYSCALL_NAME', str(v))
        s_source = s_source.replace('SYSCALL_NUMBER', str(k))
        source += s_source 

    print(source)
    return source

# map syscall numbers to syscalls
syscalls = {
    #162 : "sys_sync" ,
    62  : "sys_kill"
    #60  : "sys_exit",
    #56  : "sys_clone",
    #2   : "sys_open",
}

# Define our BPF program
b = BPF(text=gen_bpf_source(syscalls))

# Attach our kprobes 
#for k, v in syscalls.items():
    #b.attach_kprobe(event=b.get_syscall_fnname(v.split('_')[-1]), fn_name="syscall__"+v)
    #b.attach_kprobe(event=b.get_syscall_fnname("chmod"), fn_name="sys_open")
    #print("*" * 40)

b.attach_kprobe(event=b.get_syscall_fnname("kill"), fn_name="trace_sys_kill")

# header
#print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# define callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    #print("%10d \"%s\"" % (event.pid, event.args.decode('ascii')))
    print(f"PID: {event.pid}")
    print(f"ARGS: {event.args}")

b["events"].open_perf_buffer(print_event)

# format output
while 1:
    sleep(1)
    for k, v in b["counts"].items():
        name = syscalls[k.value]
        print(f"{name} : {v.value}")

    try:
        b.perf_buffer_poll()
        #(_,_,_,_,_,msg_b) = b.trace_fields()
        #msg = str.unicode(msg_b, errors='replace')
        #print(msg_b)
    except KeyboardInterrupt:
        exit()
