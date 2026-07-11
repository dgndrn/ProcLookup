#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>


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