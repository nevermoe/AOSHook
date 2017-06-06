#include "hook.h"

void get_module_range(pid_t pid, const char* module_name, long* start_addr, long* end_addr)
{
    FILE *fp;
    char *pch;
    char filename[32];
    char line[1024];
    *start_addr = 0;
    if (end_addr) {
        *end_addr = 0;
    }

    if (pid == 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                *start_addr = strtoul(pch, NULL, 16);
                pch = strtok(NULL, "-");
                if (end_addr)
                    *end_addr = strtoul(pch, NULL, 16);

                /*
                if (*start_addr == 0x8000) {
                    *start_addr -= 0x8000;

                    if (end_addr)
                        *end_addr -= 0x8000;
                }
                */
                break;
            }
        }

        fclose(fp) ;
    }
}

int hook_by_name(struct hook_t *h, char* module_name, unsigned char* func_name, void *hook_thumb, void *hook_arm)
{
    void *handle = dlopen(module_name, RTLD_NOW);
    void *func_addr = dlsym(handle, func_name);

    //get module range for self process
    long module_start_addr = 0, module_end_addr = 0;
    get_module_range(0, module_name, &module_start_addr, &module_end_addr);

    //mprotect
    mprotect((void*)module_start_addr, module_end_addr - module_start_addr, 
            PROT_READ|PROT_WRITE|PROT_EXEC);

    h->module_base = module_start_addr;

    return _hook(h, (unsigned int)func_addr, hook_thumb, hook_arm);
}

int hook_by_addr(struct hook_t *h, char* module_name, unsigned int addr, void *hook_thumb, void *hook_arm)
{
	int i;
	
    long module_start_addr = 0, module_end_addr = 0;
    get_module_range(0, module_name, &module_start_addr, &module_end_addr);
    unsigned int func_addr = module_start_addr + addr;
    
    //mprotect
    mprotect((void*)module_start_addr, module_end_addr - module_start_addr, 
            PROT_READ|PROT_WRITE|PROT_EXEC);

    h->module_base = module_start_addr;

    return _hook(h, (unsigned int)func_addr, hook_thumb, hook_arm);
}

static int _hook(struct hook_t *h, unsigned int addr, void *hook_thumb, void *hook_arm)
{
	int i;
	
    //modify function entry point
    if (addr % 4 == 0) {
        //ARM mode
        //LOGD("using ARM mode 0x%lx\n", (unsigned long)hook_arm);
        h->thumb = 0;
        h->patch = (unsigned int)hook_arm;
        h->orig = addr;
        h->jump[0] = 0xe59ff000; // LDR pc, [pc, #0]
        h->jump[1] = h->patch;
        h->jump[2] = h->patch;

        h->store[0] = 0xe8bd5fff;   //pop {r0-r12,lr}
        for (i = 0; i < 3; i++)
            h->store[i+1] = ((int*)h->orig)[i];

        h->store[4] = 0xe59ff000;   //LDR pc, [pc, #0]
        h->store[5] = h->orig + 12; //jump over first 3 instructions
        h->store[6] = h->orig + 12;

        for (i = 0; i < 3; i++)
            ((int*)h->orig)[i] = h->jump[i];
    }
    else {
        //Thumb mode
        //LOGD("using THUMB mode 0x%lx\n", (unsigned long)hook_thumb);
        if ((unsigned long int)hook_thumb % 4 == 0) {
            LOGD("warning hook is not thumb 0x%lx\n", (unsigned long)hook_thumb);
        }
        h->thumb = 1;
        h->patch = (unsigned int)hook_thumb;
        h->orig = addr;
        h->jumpt[1] = 0xb4;
        h->jumpt[0] = 0x60; // push {r5,r6}
        h->jumpt[3] = 0xa5;
        h->jumpt[2] = 0x03; // add r5, pc, #12
        h->jumpt[5] = 0x68;
        h->jumpt[4] = 0x2d; // ldr r5, [r5]
        h->jumpt[7] = 0xb0;
        h->jumpt[6] = 0x02; // add sp,sp,#8
        h->jumpt[9] = 0xb4;
        h->jumpt[8] = 0x20; // push {r5}
        h->jumpt[11] = 0xb0;
        h->jumpt[10] = 0x81; // sub sp,sp,#4
        h->jumpt[13] = 0xbd;
        h->jumpt[12] = 0x20; // pop {r5, pc}
        h->jumpt[15] = 0x46;
        h->jumpt[14] = 0xaf; // mov pc, r5 ; just to pad to 4 byte boundary

        unsigned int orig = h->orig - 1; // sub 1 to get real address
        //note in thumb mode, the pc always pre-fetch 4 bytes only after one 4 bytes are all consumed.
        if ((orig + 2) % 4 == 2) {
            //if addr of 'add r5, pc, #12' is aligned to 2 byte, then 'add r5, pc, #12' makes r5 points to offset 16
            memcpy(&h->jumpt[16], (unsigned char*)&h->patch, sizeof(unsigned int));
        }
        else {
            //if orig addr is aligned to 4 byte, then 'add r5, pc, #12' makes r5 points to offset 18
            memcpy(&h->jumpt[18], (unsigned char*)&h->patch, sizeof(unsigned int));
        }

        ((unsigned int*)h->storet)[0] = 0x5fffe8bd; //pop {r0-r12,lr}

        for (i = 0; ; ) {
            //check if the last 2 bytes in the overwritten 22 bytes contains 32 bit thumb code
            //https://stackoverflow.com/questions/28860250/how-to-determine-if-a-word4-bytes-is-a-16-bit-instruction-or-32-bit-instructio
            bits_15_11 = ((unsigned char*)orig)[i+1] & 0xf8; //0xf8 == 0b 1111 1000
            if( bits_15_11 == 0xe8 || bits_15_11 == 0xf0 || bits_15_11 == 0xf8) {
                //is 32-bit thumb instruction
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
            }
            else {
                //is 16-bit thumb instruction
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
                h->storet[i+4] = ((unsigned char*)orig)[i]; i++;
            }
            if(i >= 22)
                break;
        }

        //now i = 22 or 24
        ((unsigned int*)h->storet)[4+i] = 0xf004f8df;   //ldr pc, [pc, #4]

        if ((h->storet + i + 4) % 4 == 2) {
            ((unsigned int*)(h->storet))[i+4/*[pc,#4]*/+2/*prefetch*/] = (orig + i);
        }
        else {
            ((unsigned int*)(h->storet))[i+4/*[pc,#4]*/+4/*prefetch*/] = (orig + i);
        }
        
        for (i = 0; i < sizeof(h->jumpt); i++) {
            ((unsigned char*)orig)[i] = h->jumpt[i];
        }
    }

    //FIXME: cacheflush	
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));

	return 0;

}


void inline hook_cacheflush(unsigned int begin, unsigned int end)
{	
	const int syscall = 0xf0002;

	__asm __volatile (
		"mov	 r0, %0\n"			
		"mov	 r1, %1\n"
		"mov	 r7, %2\n"
		"mov     r2, #0x0\n"
		"svc     0x00000000\n"
		:
		:	"r" (begin), "r" (end), "r" (syscall)
		:	"r0", "r1", "r7"
		);
}

void hook_unset_jump(struct hook_t *h)
{
    int i;
    
    if (h->thumb) {
        unsigned int orig = h->orig - 1;
        for (i = 0; i < sizeof(h->storet); i++) {
            ((unsigned char*)orig)[i] = h->storet[i];
        }
    }
    else {
        for (i = 0; i < sizeof(h->store)/4; i++)
            ((unsigned int*)h->orig)[i] = h->store[i];
    }   
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

void hook_set_jump(struct hook_t *h)
{
    int i;

    if (h->thumb) {
        unsigned int orig = h->orig - 1;
        for (i = 0; i < sizeof(h->jumpt); i++)
            ((unsigned char*)orig)[i] = h->jumpt[i];
    }
    else {
        for (i = 0; i < sizeof(h->jump)/sizeof(unsigned int); i++)
            ((int*)h->orig)[i] = h->jump[i];
    }
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

