from bcc import BPF

bpf_source = """
int kprobe__sys_sync(void *ctx) 
{
  bpf_trace_printk("sys_sync() called\\n");

  return 0;
}

"""

BPF(text=bpf_source).trace_print()
