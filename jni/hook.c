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
	
    LOGD("real eph addr: 0x%x\n", h);
    //modify function entry point
    if (addr % 4 == 0) {
        //ARM mode
        LOGD("using ARM mode 0x%lx\n", (unsigned long)hook_arm);
        h->thumb = 0;
        h->patch = (unsigned int)hook_arm;
        h->orig = addr;
        //h->jump[0] = 0xe1a00000; //mov r0, r0 (nop)
        h->jump[0] = 0xe50d0008; //str r0, [sp, #-8]
        h->jump[1] = 0xe59f000c; // LDR r0, [pc, #12]
        h->jump[2] = 0xe52d0004; // push {r0}
        h->jump[3] = 0xe51d0004; // ldr r0, [sp, #-4]
        h->jump[4] = 0xe51ff004; // LDR pc, [pc, #-4]
        h->jump[5] = h->patch;
        h->jump[6] = (unsigned int)h;
        /*
        h->jump[0] = 0xe59ff000; // LDR pc, [pc, #0]
        h->jump[1] = h->patch;
        h->jump[2] = h->patch;
        h->store[0] = 0xe8bd5fff;   //pop {r0-r12,lr}
        */

        for (i = 0; i < 7; i++)
            h->store[i] = ((int*)h->orig)[i];

        h->store[7] = 0xe51ff004;   //LDR pc, [pc, #-4]
        h->store[8] = h->orig + 28; //jump over first 7 instructions

        //addr must align to page (4kb)
        int ret = mprotect((void*)((int)h->store & 0xFFFFF000), 0x1000, 
                PROT_READ|PROT_WRITE|PROT_EXEC);
        LOGD("mprotect result: %d\n", ret);

        for (i = 0; i < 7; i++)
            ((unsigned int*)h->orig)[i] = h->jump[i];
    }
    else {
        //Thumb mode
        //LOGD("using THUMB mode 0x%lx\n", (unsigned long)hook_thumb);
        if ((unsigned long int)hook_thumb % 4 == 0) {
            LOGD("warning hook is not thumb 0x%lx\n", (unsigned long)hook_thumb);
        }
        h->thumb = 1;
        //h->patch = (unsigned int)hook_thumb;
        h->patch = (unsigned int)hook_arm;
        h->orig = addr;

        //str r0, [sp, #-8]
        h->jumpt[0] = 0x4d; 
        h->jumpt[1] = 0xf8; 
        h->jumpt[2] = 0x08; 
        h->jumpt[3] = 0x0c; 
        //ldr r0, [pc, #12];
        h->jumpt[4] = 0x03; 
        h->jumpt[5] = 0x48; 
        //push {r0}
        h->jumpt[6] = 0x01; 
        h->jumpt[7] = 0xb4; 
        //ldr r0, [sp, #-4]
        h->jumpt[8] = 0x5d; 
        h->jumpt[9] = 0xf8; 
        h->jumpt[10] = 0x04; 
        h->jumpt[11] = 0x0c; 
        //ldr pc, [pc, #8]
        h->jumpt[12] = 0xdf; 
        h->jumpt[13] = 0xf8; 
        h->jumpt[14] = 0x08; 
        h->jumpt[15] = 0xf0; 


        unsigned int orig = h->orig - 1; // sub 1 to get real address
        //note in thumb mode, the pc always pre-fetch 4 bytes only after one 4 bytes are all consumed.
        if ((orig + 4) % 4 == 2) {
            //if addr of 'ldr r0, [pc, #12]' is aligned to 2 byte, then 'ldr r0, [pc, #12]' makes pc points to offset 4 + 14
            memcpy(&h->jumpt[18], (unsigned char*)&h, sizeof(unsigned int));
        }
        else {
            //if orig addr is aligned to 4 byte, then 'ldr r0, [pc, #12]' makes pc points to offset 4 + 16
            memcpy(&h->jumpt[20], (unsigned char*)&h, sizeof(unsigned int));
        }

        if ((orig + 12) % 4 == 2) {
            //if addr of 'ldr pc, [pc, #8]' is aligned to 2 byte, then 'ldr pc, [pc, #8]' makes pc points to offset 12 + 10
            memcpy(&h->jumpt[22], (unsigned char*)&h->patch, sizeof(unsigned int));

        }
        else {
            //if orig addr is aligned to 4 byte, then 'ldr pc, [pc, #8]' makes pc points to offset 12 + 12
            memcpy(&h->jumpt[24], (unsigned char*)&h->patch, sizeof(unsigned int));
        }

        //((unsigned int*)h->storet)[0] = 0x5fffe8bd; //pop {r0-r12,lr}

        for (i = 0; ; ) {
            //check if the last 2 bytes in the overwritten 22 bytes contains 32 bit thumb code
            //https://stackoverflow.com/questions/28860250/how-to-determine-if-a-word4-bytes-is-a-16-bit-instruction-or-32-bit-instructio
            unsigned char bits_15_11 = ((unsigned char*)orig)[i+1] & 0xf8; //0xf8 == 0b 1111 1000
            if( bits_15_11 == 0xe8 || bits_15_11 == 0xf0 || bits_15_11 == 0xf8) {
                //is 32-bit thumb instruction
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
            }
            else {
                //is 16-bit thumb instruction
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
                h->storet[i] = ((unsigned char*)orig)[i]; i++;
            }
            if(i >= 28)
                break;
        }

        //now i = 28 or 30
        //ldr pc, [pc, #4]
        h->storet[i] = 0xdf;
        h->storet[i+1] = 0xf8;
        h->storet[i+2] = 0x04;
        h->storet[i+3] = 0xf0;

        if ((unsigned int)(h->storet + i) % 4 == 2) {
            //(unsigned int)(h->storet[i+4/*[pc,#4]*/+2/*prefetch*/]) = (h->orig + i);
            unsigned int ret_addr = h->orig + i;
            memcpy(&h->storet[i+4+2], (unsigned char*)&ret_addr, sizeof(unsigned int));
        }
        else {
            //(unsigned int)(h->storet[i+4/*[pc,#4]*/+4/*prefetch*/]) = (h->orig + i);
            unsigned int ret_addr = h->orig + i;
            memcpy(&h->storet[i+4+4], (unsigned char*)&ret_addr, sizeof(unsigned int));
        }
        
        for (i = 0; i < 28; i++) {
            ((unsigned char*)orig)[i] = h->jumpt[i];
        }
        
        //addr must align to page (4kb)
        int ret = mprotect((void*)((int)h->storet & 0xFFFFF000), 0x1000, 
                PROT_READ|PROT_WRITE|PROT_EXEC);
        LOGD("mprotect result: %d\n", ret);
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

