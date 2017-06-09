#include "hook.h"

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

const int long_size = sizeof(long);

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

static int 
read_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
    unsigned long *p; 
    int i;

    for (p = buf, i = 0; i < nlong; p++, i++)
        if ((*p = ptrace(PTRACE_PEEKTEXT, pid, (void *)(pos+(i*4)), (void *)*p)) < 0)
            return -1; 
    return 0;
}

void putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}

long get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
    long local_handle, remote_handle;

    get_module_range(0, module_name, &local_handle, 0);
    get_module_range(target_pid, module_name, &remote_handle, 0);
    printf("remote %s handle = 0x%x\n", module_name, (unsigned int)remote_handle);

    long ret_addr = (long)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);

    return ret_addr;
}


int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
    uint32_t i;
    for (i = 0; i < num_params && i < 4; i ++) {
        regs->uregs[i] = params[i];
    }

    //
    // push remained params onto stack
    //
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        putdata(pid, regs->ARM_sp, (char*)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;
    
    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int status = 0;
    wait(&status);
    /*
    while (status != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        printf("waitpid\n");
        waitpid(pid, &status, WUNTRACED);
    }
    */

    return 0;
}


int inject_so(pid_t pid,char* so_path, char* function_name,char* parameter)
{
    struct pt_regs old_regs,regs;
    long mmap_addr, dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr;

    //save old regs
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    memcpy(&regs, &old_regs, sizeof(regs));

    //get remote addres
    printf("getting remote addres:\n");
    /*
    mmap_addr = get_remote_addr(pid, libc_path, (void *)mmap);
    dlopen_addr = get_remote_addr( pid, libc_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( pid, libc_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( pid, libc_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( pid, libc_path, (void *)dlerror );
    */
    mmap_addr = get_remote_addr(pid, libc_path, (void *)mmap);
    dlopen_addr = get_remote_addr( pid, linker_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( pid, linker_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( pid, linker_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( pid, linker_path, (void *)dlerror );
    
    printf("mmap_addr=%p dlopen_addr=%p dlsym_addr=%p dlclose_addr=%p\n",
    (void*)mmap_addr,(void*)dlopen_addr,(void*)dlsym_addr,(void*)dlclose_addr);
    

    //mmap
    long parameters[10];
    parameters[0] = 0; //address
    parameters[1] = 0x4000; //size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; //WRX
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; //flag
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset
    
    ptrace_call(pid, mmap_addr, parameters, 6, &regs);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    long map_base = regs.ARM_r0;
    printf("map_base = %p\n", (void*)map_base);

    /*
    //dlerror
    printf("calling dlerror()");
    ptrace_call(pid, dlerror_addr, parameters, 0, &regs);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    long error_addr = regs.ARM_r0;
    printf("before, error = %s\n",(char*) error_addr);
    */

    //dlopen
    //printf("save so_path = %s to map_base = %p\n", so_path, (void*)map_base);
    putdata(pid, map_base, so_path, strlen(so_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;

    ptrace_call(pid, dlopen_addr, parameters, 2, &regs);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    long handle = regs.ARM_r0;
    
    //printf("handle = %p\n",(void*) handle);

    /*
    //dlerror
    printf("calling dlerror()");
    ptrace_call(pid, dlerror_addr, parameters, 0, &regs);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    error_addr = regs.ARM_r0;
    printf("after error = %s\n",(char*) error_addr);
    */

    //dlsym
    //printf("save function_name = %s to map_base = %p\n", function_name, (void*)map_base);
    putdata(pid, map_base, function_name, strlen(function_name) + 1);

    parameters[0] = handle;
    parameters[1] = map_base;

    ptrace_call(pid, dlsym_addr, parameters, 2, &regs);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    long function_ptr = regs.ARM_r0;

    printf("init_func addr = %p\n", (void*)function_ptr);

    //function_call
    //printf("save parameter = %s to map_base = %p\n", parameter, (void*)map_base);
    putdata(pid, map_base, parameter, strlen(parameter) + 1);

    parameters[0] = map_base;

    ptrace_call(pid, function_ptr, parameters, 1, &regs);

    //restore old regs
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);

    if (ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }
}


int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s <pid to be traced>\n", argv[0]);
        return 1;
    }
                                                                                                     
    pid_t pid;
    int status;
    pid = atoi(argv[1]);

    char* so_path = "/data/local/tmp/libinject.so";
    char* init_func = "init_func";
    char* parameter = "init_func called, initializing";

    
    if(0 != ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    {
        printf("Trace process failed:%d.\n", errno);
        return 1;
    }
    
    wait(&status);
    inject_so(pid, so_path, init_func, parameter);


    /*
    //for debug
    wait(&status);
    struct pt_regs regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("pc = 0x%x\tlr=0x%x\n", regs.ARM_pc, regs.ARM_lr);
    unsigned long buf[20];
    read_mem(pid, buf, 20, regs.ARM_pc);
    int i = 0;
    for(i = 0 ; i < 5 ; i++){
        printf("%x\n", buf[i]);
    }
    
    while(1) {
    }
    */

    ptrace(PTRACE_DETACH, pid, NULL, 0);
    
    return 0;
}
