#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define _GNU_SOURCE
#include <sys/uio.h>


#define LOGF(...) fprintf(logfd,__VA_ARGS__); \                 
                  printf(__VA_ARGS__) \


#define READ_1 1
#define READ_2 2
#define READ_4 4
#define READ_8 8
#define READ_16 16   
#define READ_32 32
#define READ_64 64
#define READ_512 512
#define READ_4096 4096 

#define WRITE_1 1
#define WRITE_2 2
#define WRITE_4 4
#define WRITE_8 8
#define WRITE_16 16   
#define WRITE_32 32
#define WRITE_64 64
#define WRITE_512 512
#define WRITE_4096 4096 




#define READ 1
#define WRITE 2
#define EXIT 3

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];
    unsigned long offset;
    char dev[8];
    unsigned long inode;
    char pathname[256];
} memory_region_t;

void init();
void out();
int read_process_memory(pid_t pid, uint64_t addr, size_t size);
int write_process_memory(pid_t pid, uint64_t addr, size_t size);
void parse_procname();
int pid_by_name(char* procname);
void parse_stack(memory_region_t region);
void read_address(pid_t pid, unsigned long address, size_t size_t);
void parse_maps(int pid);
bool callme(int pid, unsigned long addr,bool exit);
void read_file(char *filepath);
void parse_region(memory_region_t region, uint16_t flag);
int ptrace_scope_init();
int ptrace_scope_out();
void log_init();
void LOG(char *message);
void log_out();
char *date();


ssize_t process_vm_readv(pid_t pid,
				const struct iovec *local_iov,
				unsigned long liovcnt,
				const struct iovec *remote_iov,
				unsigned long riovcnt,
				unsigned long flags);

ssize_t process_vm_writev(pid_t pid,
                        const struct iovec *local_iov,
                        unsigned long liovcnt,
                        const struct iovec *remote_iov,
                        unsigned long riovcnt,
                        unsigned long flags);


char const_proc[66][20] = {
".",
"..",
"fb",
"fs",
"bus",
"dma",
"irq",
"net",
"sys",
"tty",
"acpi",
"keys",
"kmsg",
"misc",
"mtrr",
"scsi",
"stat",
"iomem",
"kcore",
"locks",
"swaps",
"vmnet",
"asound",
"crypto",
"driver",
"mdstat",
"mounts",
"uptime",
"vmstat",
"cgroups",
"cmdline",
"cpuinfo",
"devices",
"ioports",
"loadavg",
"meminfo",
"modules",
"sysvipc",
"version",
"consoles",
"kallsyms",
"pressure",
"slabinfo",
"softirqs",
"zoneinfo",
"buddyinfo",
"diskstats",
"key-users",
"schedstat",
"bootconfig",
"interrupts",
"kpagecount",
"kpageflags",
"partitions",
"timer_list",
"execdomains",
"filesystems",
"kpagecgroup",
"vmallocinfo",
"pagetypeinfo",
"dynamic_debug",
"latency_stats",
"sysrq-trigger",
"version_signature",
"self",
"thread-self"};