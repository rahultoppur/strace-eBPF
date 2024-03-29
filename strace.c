#include <linux/sched.h> 
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <uapi/linux/in.h>
#include <asm/fcntl.h>
#include <asm/unistd_64.h>

struct data_t {

    /* PID-specific details */
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
    
    /* Filenames and arguments */
    char filename[16];

    char argv0[40];
    char argv1[20];
    char argv2[20];
    char argv3[20];

    /* IP-specific details */
    u32 s_addr;
    u16 port;

    /* Return value */
    long ret; 

    /* Used by mmap, statfs, brk */
    long address; 

    /* Should we stop tracing? */
    int end; 
};

/* 
 * Create hashmap from syscall ID to data_t entry. 
 * Lookup syscall in exit tracepoint to fill out
 * return code, then submit to buffer.
 */
BPF_HASH(map, int, struct data_t); 
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    /* Trace if PID or PPID matches filter */
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    PID_FILTER_BEGIN
    
    int key = (int)args->id; /* Use syscall ID as key */

    struct data_t *p  = map.lookup(&key);
    if (p == NULL) { return 0; }

    (*p).ret = args->ret; /* Update return value based on sys_exit */ 
    
    /* Submit event to the buffer */
    events.perf_submit(args, &(*p), sizeof(*p));

    PID_FILTER_END

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    /* Obtain PID and PPID. Only trace if both are equal to same value. */
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
        case __NR_read: 
        {
            data.fd = args->args[0];                                                /* fd */ 
            data.count = args->args[2];                                             /* bytes read */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[1]); /* buf */
            break; 
        }
        case __NR_write: 
        {
            data.fd = args->args[0];                                                /* fd */ 
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[1]); /* buf */
            data.count = args->args[2];                                             /* bytes written */
            break;
        }
        case __NR_open: 
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
            data.flags = args->args[1];                                                   /* flags */
            data.mode = args->args[2];                                                    /* mode */
            break;
        }
        case __NR_close: 
        {
            data.fd = args->args[0]; /* fd */
            break;
        }
        case __NR_fstat: 
        {
            data.fd = args->args[0]; /* fd */
            break;
        }
        case __NR_mmap:
        {
            data.address = args->args[0]; /* address */
            data.fd = args->args[4];      /* fd */
            break;
        }
        case __NR_brk:
        {  
            data.address = args->args[0]; /* address */
            break;
        }
        case __NR_pread64:
        {
            data.fd = args->args[0];
            bpf_probe_read_str(&data.argv0, sizeof(data.argv0), (void *)args->args[1]); /* buf */
            data.count = args->args[2];                                                 /* count */
            break;
        }
        case __NR_access: 
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
            data.mode = args->args[1];                                                    /* mode */
            break;
        }
        case __NR_dup: 
        {
            data.fd = args->args[0]; /* fd */
            break;
        }
        case __NR_dup2: 
        {
            data.fd = args->args[0];     /* fd */
            data.new_fd = args->args[1]; /* new fd */
            break;
        }
        case __NR_connect: 
        {
            /* socket-specific details for obtaining IP */
            struct sockaddr* sock;
            bpf_probe_read(&sock, sizeof(sock), (void *)args->args[1]);
            struct sockaddr_in* addr_in = (struct sockaddr_in*)&sock;
            data.s_addr = addr_in->sin_addr.s_addr;                     /* IP as u32 */
            data.port = addr_in->sin_port;                              /* port */
            break;
        }
        case __NR_execve: 
        {
            char *my_args[4];  /* Only store up to 4 args for argv */
            bpf_probe_read(&my_args, sizeof(my_args), (void *)args->args[1]); 
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
            bpf_probe_read(&data.argv0, sizeof(data.argv1), (void *)my_args[0]);          /* argv[0] */
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)my_args[1]);          /* argv[1] */
            bpf_probe_read(&data.argv2, sizeof(data.argv1), (void *)my_args[2]);          /* argv[2] */
            bpf_probe_read(&data.argv3, sizeof(data.argv1), (void *)my_args[3]);          /* argv[3] */
            break;
        }
        case __NR_kill: 
        {
            data.pid = args->args[0];    /* pid */
            data.signal = args->args[1]; /* signal */
            break;
        }
        case __NR_link: 
        {
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[1]); /* old name */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        case __NR_unlink: 
        {
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[0]); /* pathname */
            break;
        }
        case __NR_symlink:
        {
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[1]); /* old name */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        case __NR_chmod:
        {
            bpf_probe_read(&data.filename, sizeof(data.filename), (void *)args->args[0]); /* filename */
            data.mode = args->args[1];                                                    /* mode */
            break;
        }
        case __NR_statfs:
        {
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (void *)args->args[0]); /* pathname */
            data.address = args->args[1];                                           /* address */
            break;
        }
        case __NR_getdents64: 
        {
            /* Store only a single filename */
            struct linux_dirent64 dir_entries[2];
            data.fd = args->args[0];                                                        /* fd */						  
            bpf_probe_read(&dir_entries, sizeof(dir_entries), (void *)args->args[1]);

            data.d_reclen = dir_entries[0].d_reclen;                                        /* Length of record */
            data.d_inode = dir_entries[0].d_ino;                                            /* Inode */
            data.d_type = dir_entries[0].d_type;                                            /* D-type */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (char *)dir_entries[0].d_name); /* Filenames */
            break;
        }
        case __NR_exit_group: 
        {
            data.count = args->args[0];
            data.end = 1;                                  /* Set end tracing to 1 if we see call to exit_group */
            events.perf_submit(args, &data, sizeof(data)); /* Submit record to be handled by the perf buffer */
            break;
        }
        case __NR_openat: 
        {
            data.fd = args->args[0];                                                      /* fd */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (const char*)args->args[1]);  /* filename */
            data.flags = args->args[2];                                                   /* file flags */
            data.mode = args->args[3];                                                    /* file mode */
            break;
        }
        case __NR_symlinkat: 
        {   
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (void *)args->args[0]); /* old name */
            data.fd = args->args[1];                                                /* new fd */
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (void *)args->args[2]); /* new name */
            break;
        }
        default:
            /* Just populate argv0 -> argv3 with char representation of values for now */
            bpf_probe_read(&data.argv0, sizeof(data.argv0), (const char*)args->args[0]);  
            bpf_probe_read(&data.argv1, sizeof(data.argv1), (const char*)args->args[1]);  
            bpf_probe_read(&data.argv2, sizeof(data.argv2), (const char*)args->args[2]);  
            bpf_probe_read(&data.argv3, sizeof(data.argv3), (const char*)args->args[3]);  
            break;
    }
    
    int key = (int)args->id; /* Make key syscall ID */
    /* 
     * Update map regardless--always want syscall ID
     * to point to latest data entry
     */
    map.update(&key, &data); 

    PID_FILTER_END
    return 0;
}
