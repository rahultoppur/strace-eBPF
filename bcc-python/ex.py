from bcc import BPF
from datetime import datetime

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

//int syscall__open(struct pt_regs *ctx, const char __user *filename) {
int my_execve(struct pt_regs *ctx, 
               const char __user *filename, 
               const char __user *const __user *__argv)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    //bpf_trace_printk("PID is: %d\n", pid);



    if (pid == 420992) {
        //bpf_trace_printk("Tracing execve syscall...\n");
        //bpf_trace_printk("Filename is: %s\n", filename);
        bpf_trace_printk("Args are: %s\n", __argv);
    }

    
	return 0;
}
"""

bpf = BPF(text=BPF_PROGRAM)
#bpf.attach_kprobe(event=bpf.get_syscall_fnname("openat"), fn_name="my_openat")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("openat"), fn_name="my_execve")

while True:
	try:
		(_, _, _, _, _, msg_b) = bpf.trace_fields()
		msg = msg_b.decode('utf8')
		print(datetime.now().strftime("%H:%M:%S"), msg)
	except ValueError:
		continue
	except KeyboardInterrupt:
		break
