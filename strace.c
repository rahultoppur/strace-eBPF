#include <linux/sched.h>
//#include <net/sock.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/in.h>
struct data_t {
    // Stack space is shared, so account for all types of possibilities. Mostly just a combo of ints and char[N].
    u32 pid;
    int syscall_id;
    
    char comm[TASK_COMM_LEN];

    int fd;
    int count;
    int flags;
    int signal;
    unsigned short mode;
 
    char filename[16];
 
    char argv0[20];
    char argv1[20];
    char argv2[20];
    char argv3[20];

    // IP-specific details
    u32 s_addr;
    u16 port;
};
BPF_PERF_OUTPUT(events);
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    // For each syscall in here, look up it's ID and correlate it. Then, depending on its
    // params, only print out it's related arguments.
    // Obtain pid and ppid. Only trace if pid is equal to the value 
    // we specify or if the ppid is also equal to the same value.

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    PID_FILTER_BEGIN

    struct data_t data = {};
    data.pid = pid;
    data.syscall_id = args->id; 

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    switch(args->id) {
        case 0: /* READ */
        {
            data.fd = args->args[0];                                        /* fd */ 
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[1]); /* buf */
            data.count = args->args[2];                                     /* bytes read */
            break; 
        }
        case 1: /* WRITE */
        {
            data.fd = args->args[0];                                        /* fd */ 
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[1]); /* buf */
            data.count = args->args[2];                                     /* bytes written */
            break;
        }
        case 2: /* OPEN */
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]);
            data.flags = args->args[1];
            data.mode = args->args[2];
            break;
        }
        case 3: /* CLOSE */
        {
            data.fd = args->args[0];
            break;
        }
        case 42: /* CONNECT */
        {
            /* socket-specific details for obtaining IP */
            struct sockaddr* sock;
            struct sockaddr_in* addr_in = (struct sockaddr_in*)&sock;
            bpf_probe_read(&sock, sizeof(sock), (void *)args->args[1]);
            data.s_addr = addr_in->sin_addr.s_addr; /* IP as u32 */
            data.port = addr_in->sin_port;          /* port */
            break;
        }
        case 59: /* EXECVE */
        {
            char *my_args[10];  /* args for argv */
            bpf_probe_read(&my_args, sizeof(my_args), (void *)args->args[1]); 
            bpf_probe_read_str(&data.filename, sizeof(data.argv1), (void *)args->args[0]); /* filename */
            bpf_probe_read_str(&data.argv0, sizeof(data.argv1), (void *)my_args[0]);       /* argv[0] */
            bpf_probe_read_str(&data.argv1, sizeof(data.argv1), (void *)my_args[1]);       /* argv[1] */
            bpf_probe_read_str(&data.argv2, sizeof(data.argv1), (void *)my_args[2]);       /* argv[2] */
            bpf_probe_read_str(&data.argv3, sizeof(data.argv1), (void *)my_args[3]);       /* argv[3] */
            break;
        }
        case 62: /* KILL */
        {
            data.pid = args->args[0]; 
            data.signal = args->args[1];
            break;
        }
        case 257: /* OPENAT */
        {
            data.fd = args->args[0];     /* fd */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (const char*)args->args[1]);  /* filename */
            data.flags = args->args[2];  /* file flags */
            data.mode = args->args[3];   /* file mode */
            break;
        }
        default:
            // Just populate argv0 -> argv3 with char representation of values? Not sure...
            break;
    }

    events.perf_submit(args, &data, sizeof(data));
    PID_FILTER_END
    return 0;
}
