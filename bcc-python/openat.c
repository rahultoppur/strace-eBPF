#include <uapi/linux/ptrace.h>

struct data_t {
    char filename[25];
};

BPF_PERF_OUTPUT(events);


struct syscalls_sys_enter_openat_args {
	int dfd;
	const char * filename;	
	int flags;	
	unsigned short mode;
};


int printarg(struct syscalls_sys_enter_openat_args *args) {
    struct data_t data = {};

    bpf_probe_read(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
	bpf_trace_printk("hello, world!");
	return 0;
}



/*
int printarg(void* ctx) {
    bpf_trace_printk("hello!");
    return 0;
}
*/

