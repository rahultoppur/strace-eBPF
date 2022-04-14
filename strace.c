#include <linux/sched.h>
//#include <net/sock.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/dirent.h>
#include <linux/compat.h>
#include <asm/fcntl.h>
struct data_t {
    // Stack space is shared, so account for all types of possibilities. Mostly just a combo of ints and char[N].
    u32 pid;
    int syscall_id;
    
    char comm[TASK_COMM_LEN];

    /* File descriptors */
    int fd;
    int new_fd;

    int count;
    int flags;
    int signal;

    /* Files and directories */
    unsigned short mode;
    u64 d_inode;
    unsigned char d_type;
    unsigned short d_reclen;

    char filename[16];

    char argv0[40];
    char argv1[20];
    char argv2[20];
    char argv3[20];

    // IP-specific details
    u32 s_addr;
    u16 port;
    long ret;

    int end; // end tracing?
    
};

/*
struct data_out_t {
    short out;
    char comm[TASK_COMM_LEN];
    u32 pid;
    int syscall_id;
    long ret;
};
*/

BPF_PERF_OUTPUT(events);
BPF_HASH(map, int, struct data_t); // Create hashmap from PID to data_t entry. Will then lookup in exit and fill out return code, then submit to buffer.
//BPF_PERF_OUTPUT(events_out);

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{

    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    PID_FILTER_BEGIN

    //struct data_t data = {};
    int key = (int)args->id;
    //struct data_t* value;

    // Perform null check here!
    struct data_t *p  = map.lookup(&key);
    if (p == NULL) {
        return 0;
    }

    /* Update return value based on sys_exit */ 
    (*p).ret = args->ret;

 
    //data.pid = pid;
    //data.syscall_id = args->id; 
    //value->ret = args->ret; // Populate return-value data
    //bpf_get_current_comm(&data.comm, sizeof(data.comm));

    /*
    struct data_t output = {};
    output.fd = p->fd;
    output.new_fd = p->new_fd;
    output.syscall_id = p->syscall_id;
    //output.comm = p->comm;
    output.count = p->count;
    output.flags = p->flags;
    output.signal = p->signal;
    output.mode = p->mode;    
    output.d_inode = p->d_inode;
    output.d_type = p->d_type;
    output.d_reclen = p->d_reclen;
    
    //output.filename = p->filename;
    //output.argv0 = p->argv0;
    //output.argv1 = p->argv1;
    //output.argv2 = p->argv2;
    //output.argv3 = p->argv3;
    output.s_addr = p->s_addr;
    output.port = p->port;
    output.ret = p->ret;
    */

    //events.perf_submit(args, &output, sizeof(output)); // Submit the event to the buffer.
    events.perf_submit(args, &(*p), sizeof(*p)); // Submit the event to the buffer.

    PID_FILTER_END
    return 0;
}


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
        case 5: /* FSTAT */
        {
            data.fd = args->args[0];
            break;
        }
        case 21: /* ACCESS */
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]);
            data.mode = args->args[1];
        }
        case 32: /* DUP */
        {
            data.fd = args->args[0];
            break;
        }
        case 33: /* DUP2 */
        {
            data.fd = args->args[0];
            data.new_fd = args->args[1];
            break;
        }
        case 42: /* CONNECT */
        {
            /* socket-specific details for obtaining IP */
            struct sockaddr* sock;
            bpf_probe_read(&sock, sizeof(sock), (void *)args->args[1]);
            struct sockaddr_in* addr_in = (struct sockaddr_in*)&sock;
            data.s_addr = addr_in->sin_addr.s_addr; /* IP as u32 */
            data.port = addr_in->sin_port;          /* port */
            break;
        }
        case 59: /* EXECVE */
        {
            char *my_args[4];  /* Only store up to 4 args for argv */
            bpf_probe_read(&my_args, sizeof(my_args), (void *)args->args[1]); 
            bpf_probe_read_str(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
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
        case 86: /* LINK */
        {
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[1]); /* old name */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        case 87: /* UNLINK */
        {
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[0]); /* pathname */
            break;
        }
        case 88: /* SYMLINK */
        {
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[1]); /* old name */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        case 90: /* CHMOD */
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
            data.mode = args->args[1];
            break;
        }
        case 217: /* GETDENTS64 */
        {
            /* Store only a single filename */
            struct linux_dirent64 dir_entries[2];
            data.fd = args->args[0]; /* fd */						  
            bpf_probe_read(&dir_entries, sizeof(dir_entries), (void *)args->args[1]);

            data.d_reclen = dir_entries[0].d_reclen; /* Length of record */
            data.d_inode = dir_entries[0].d_ino; /* Inode */
            data.d_type = dir_entries[0].d_type; /* D-type */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (char *)dir_entries[0].d_name); /* Filenames */
            break;
        }
        case 231: /* EXIT_GROUP */
        {
            data.count = args->args[0];
            data.end = 1; /* Set end tracing to 1 if we see exit_group() syscall */
            /* submit a record to perf buffer so that print_even can handle it */
            events.perf_submit(args, &data, sizeof(data));
            break;
        }
        case 257: /* OPENAT */
        {
            data.fd = args->args[0];     /* fd */
            /*
            char msg[9] = "AT_FDCWD";
            if (data.fd == AT_FDCWD) {
                bpf_probe_read(&data.argv1, sizeof(data.argv1), msg);
            }            
            */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (const char*)args->args[1]);  /* filename */
            data.flags = args->args[2];  /* file flags */
            data.mode = args->args[3];   /* file mode */
            break;
        }
        case 266: /* SYMLINKAT */
        {   
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[0]); /* old name */
            data.fd = args->args[1]; /* new fd */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        default:
            // Just populate argv0 -> argv3 with char representation of values? Not sure...
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (const char*)args->args[0]);  
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (const char*)args->args[1]);  
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (const char*)args->args[2]);  
            bpf_probe_read(&data.argv3, sizeof(data.argv3), (const char*)args->args[3]);  
            break;
    }

    int key = (int)args->id; // Make key syscall id
    map.update(&key, &data); // Update map regardless, always want syscall id to point to latest data entry.
    //map.insert(&key, &data); // Update map regardless, always want syscall id to point to latest data entry.

    //events.perf_submit(args, &data, sizeof(data));
    PID_FILTER_END
    return 0;
}
