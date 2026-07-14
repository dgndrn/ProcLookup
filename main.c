#include "lib.h"

struct stack {
    unsigned long start;
    unsigned long end;
    char protection[4];
}stack;

struct heap {
    unsigned long start;
    unsigned long end;
    char protection[4];
}heap;

struct proclist {
    char procname[600][1024];
    int pid[600];
    int procnum;
} proclist;

struct map {
    
   struct stack stack;
   struct heap heap;

    uint64_t text_section;
    char region_name[2][20];

    #define STACK_FLAG 0
    #define HEAP_FLAG 1
    uint16_t flag;
    
    struct proclist proclist;
}map;


FILE* logfd;

int main(int argc, char** argv){
    
    if(argc != 2){
        printf("Usage \"sudo ./lookup [Procname]\"\n");
        return -1;
    }

    init();

    memcpy(map.region_name[0],"[stack]",8);
    memcpy(map.region_name[1],"[heap]",7);
   
    u_int64_t addr = 0;   
    pid_t pid = pid_by_name(argv[1]);
    
    parse_maps(pid);
    
    bool exit = false;
    
    while(!exit){

       exit = callme(pid,addr,exit);
    }

   out(); 
   return 0;
}

bool callme(int pid,unsigned long addr,bool _exit){
 
    size_t size = READ_32;
    int input,err = 0;
    
    printf("1- Read\n2- Write\n3- Exit\n> ");
    err = scanf("%d",&input);
    if(err == 0){   
        LOGF("Wrong Input\n");
        exit(-1);
    }

    switch (input){

    case READ:
        
        LOG("read address:");    

        scanf("%lx",&addr);
        
        LOGF("read address: 0x%lx\n",addr);    

        if(addr == 0){
            _exit = true;
        }
        
        read_address(pid,addr,size);

        return _exit;
    
    case WRITE:

        LOG("write address:");    
        
        scanf("%lx",&addr);
        
        err = write_process_memory(pid, addr, size); 
        if(err){
            out();
            exit(-1);
        }
    break;

    case EXIT:
        exit(0);

    default:
        LOGF("Wrong Input\n");
        break;
    }

}

void read_file(char *filepath){
    
    FILE* fd = fopen(filepath,"rb");
    
    char line[512];

    while (fgets(line, sizeof(line), fd)) {

        for(int i = 0;i < 512;i++) {
            LOGF("X",line[i]);
        }
    }
    fclose(fd);
}

void parse_maps(int pid) {
    
    char path[64];

    if (pid == 0) {
        snprintf(path, sizeof(path), "/proc/self/maps");
    } else {
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    }

    FILE *file = fopen(path, "r");
    
    if (!file) {
        
        LOG("Failed to open maps file");
        
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        memory_region_t region;
        region.pathname[0] = '\0';

        int matched = sscanf(line, "%lx-%lx %4s %lx %7s %lu %255[^\n]",
                             &region.start, &region.end, region.perms,
                             &region.offset, region.dev, &region.inode,
                             region.pathname);

        if (matched >= 6) {
            char *trimmed_path = region.pathname;
            while (*trimmed_path == ' ' || *trimmed_path == '\t') {
                trimmed_path++;
            }
            
            LOGF("0x%012lx-0x%012lx %s %s\n", 
                   region.start, region.end, region.perms, trimmed_path);
            
            for(int i=0;i< 2;i++) 
            if( strcmp(map.region_name[i], region.pathname) == 0) {       
               map.flag = i; 
               parse_region(region, map.flag);
            }

        }
    }

    fclose(file);
}

int read_process_memory(pid_t pid, uint64_t addr, size_t size){

    unsigned char buffer[READ_4096];

    struct iovec local = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer)
    };

    struct iovec remote = {
        .iov_base = (void*)addr,
        .iov_len = sizeof(buffer)
    };

    ssize_t nread = process_vm_readv(
        pid,
        &local, 1,
        &remote, 1,
        0);

    if(nread < 0)
    {
        LOGF("read address failed for %lx\n",addr);
        return 1;
    }

    LOGF("Read %zd bytes\n", size);

    for(int i=0;i<size;i++){

        LOGF("%02X ", buffer[i]);
    }

    for(int i=0;i<size;i++){

        LOGF("%C", buffer[i]);
    }

    LOGF("\n");
    
    return 0;
}

int write_process_memory(pid_t pid, uint64_t addr, size_t size){

    
    unsigned char buffer[WRITE_64];
    LOGF("Enter Buffer:");
    scanf("%s",&buffer);

    struct iovec local = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer)
    };

    struct iovec remote = {
        .iov_base = (void*)addr,
        .iov_len = sizeof(buffer)
    };

    ssize_t nwrited = process_vm_writev(
        pid,
        &local, 1,
        &remote, 1,
        0);

    if(nwrited == -1)
    {
        switch (errno)
        {
        case EPERM:
            LOGF("Operation not permitted! Possibly read only zone!");
            break;

        case ESRCH:
            LOGF("No such process! Check pid");
            break;

        case EFAULT:
            LOGF("Bad address");
            break;

        default:
            break;
        }
        LOGF("remote process write failed for %lx\n",addr);
        return 1;
    }

    LOGF("%zd bytes written\n", size);

    read_process_memory(pid, addr, size);
    
    return 0;


}

void parse_stack(memory_region_t region){
    
    map.stack = stack;
    stack.start = region.start;
    stack.end = region.end;
    memcpy(stack.protection,region.perms,4); 

    LOGF("Stack\n0x%012lx-0x%012lx %s\n",stack.start,stack.end,stack.protection);       
}

void read_address(pid_t pid, unsigned long address, size_t size){

    read_process_memory(pid, address, size);
}

void parse_region(memory_region_t region, uint16_t flag){

    switch (flag) {

    case STACK_FLAG:
        
        map.stack = stack;
        stack.start = region.start;
        stack.end = region.end;
        memcpy(stack.protection,region.perms,4);    
     //   LOGF("Stack\n0x%012lx-0x%012lx %s\n",stack.start,stack.end,stack.protection);   
        break;

    case HEAP_FLAG:
       
        map.heap = heap;
        heap.start = region.start;
        heap.end = region.end;
        memcpy(heap.protection,region.perms,4);      
    //    LOGF("Heap\n0x%012lx-0x%012lx %s\n",heap.start,heap.end,heap.protection);   
        break;

    default:
        
        char errmsg[100];
        snprintf(errmsg,sizeof(errmsg),"Error!: Unknown flag detected: %d",flag);
        LOG(errmsg);
        exit(-7);
        break;
    }
}

void log_init(){

    logfd = fopen("./ProcLookup.log","a");
    
    if(logfd < 0){
        
        printf("ProcLookup.log couldn't open");
        exit(-1);
    }
        setenv("TZ", "Europe/Istanbul", 1);
        tzset();
        LOG("INIT\n");

        return;
}

void LOG(char *message){

    char *test = date();
    char tt2[400];
    char _message[120] = "[LOG] ";
    memcpy(tt2,test,20);
    strcat(tt2,_message);
    strcat(tt2,message);
    strcat(tt2,"\n");
    printf("%s",message);
    fprintf(logfd,"%s",tt2);
    return;
}

void log_out(){
    
    LOG("OUT\n");
    fclose(logfd);
    return;
}

int ptrace_scope_init(){

    FILE *fd = fopen("/proc/sys/kernel/yama/ptrace_scope","rb");
    if(fd < 0){
        LOG("failed open file:/proc/sys/kernel/yama/ptrace_scope");
        log_out();
        exit(-1);
    }
    
    char buffer[1];
    int val = -1;

    fread(buffer,sizeof(buffer),sizeof(buffer),fd);
     
    val = atoi(buffer);
    
    if(val == 1){
        LOGF("current ptrace value: %d\n",val);
        
        fclose(fd);
        
        fd = fopen("/proc/sys/kernel/yama/ptrace_scope","wb");
        
        if(fd <= 0){
            LOG("Failed open file. Use sudo!\n");
            log_out();
            exit(-1);
        }
        
        fclose(fd);
        system("echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"); 
        LOG("ptrace value set to 0\n");
        
        return 0;
    }

    fclose(fd);
    return 0;
}

int ptrace_scope_out(){
    system("echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope");
    LOG("ptrace value set to 1\n");
    return 0;
}

int pid_by_name(char* procname){

    for(int i = 0; i<map.proclist.procnum; i++){

        if(strcmp(procname, map.proclist.procname[i]) == 0){
            LOGF("found: %s pid: %d \n",map.proclist.procname[i],map.proclist.pid[i]);
            return map.proclist.pid[i];
        }
    }
    LOGF("process couldn't find: %s",procname);
    
    exit(-1);
}

void parse_procname(){

    map.proclist = proclist;
    char proclist[1024][1024];
    struct dirent *de;  
    DIR *dr = opendir("/proc");

    if (dr == NULL)  
    {
        LOG("Could not open /proc directory");
        ptrace_scope_out();
        log_out();
        return;
    }

    int counter = 0;
    while ((de = readdir(dr)) != NULL){
            memcpy(proclist[counter], de->d_name,sizeof(de->d_name));
            counter++;
    }        

    closedir(dr);
   
    char nullit[13] = "NULL";  
    for(int i=0; i < 66; i++){
        for(int j=0; j < counter; j++){
            if(strcmp(const_proc[i],proclist[j]) == 0) {
                memcpy(proclist[j],nullit,sizeof(nullit));  
            } 
        }
    }

    int counter2 = 0;
    for(int i = 0; i < counter; i++){
        if(strcmp(proclist[i],"NULL") != 0){
            map.proclist.pid[counter2] = atoi(proclist[i]);
            counter2++;
        }
    }

    for(int i=0; i< counter2; i++){
        char filepath[100];
        char buffer[100];
        snprintf(filepath, sizeof(filepath), "/proc/%d/comm", map.proclist.pid[i]);
        FILE *files = fopen(filepath,"rb");
        fgets(buffer, sizeof(buffer), files);
        buffer[strlen(buffer)-1] = '\0';
        memcpy(map.proclist.procname[i],buffer,sizeof(buffer)); 
        LOGF("pid: %d comm: %s\n",map.proclist.pid[i], map.proclist.procname[i]);
        map.proclist.procnum = counter2;

    }
    LOGF("Size of list : %d\n",counter2+1);
    
    return;
}

void init(){

    log_init();
    ptrace_scope_init();
    parse_procname();
    return;
}

void out(){

    ptrace_scope_out();
    log_out();
    return;
}

char *date(){

    char *_ctime;
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    char buffer[80];
    strftime(buffer, sizeof(buffer), "%d.%m.%Y - %H:%M:%S", timeinfo);
    _ctime = (char *)buffer;
    return _ctime;
}


