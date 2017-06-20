#include "hook.h"
#include <android/log.h>


static struct hook_t eph;
    
extern int hook_arm(int p0,int p1,int p2,int p3,int p4,int p5);

__attribute__ ((naked)) int hook_thumb(int p0,int p1,int p2,int p3,int p4,int p5)
{
    /*
    __asm __volatile(
        //save r5 to label save_r5
        "push   {r4}\n"
        "ldr    r4, =save_r5\n"
        "str    r5, [r4]\n"

        //save lr to label lr
        //note hi registers cannot use str or ldr instruction directly
        "ldr    r4, =save_lr\n"
        "mov    r5, lr\n"
        "str    r5, [r4]\n"

        //restore r4
        "pop    {r4}\n"

        "push   {lr}\n"
        //"ldr.w   lr, [sp], #4\n"
        "pop    {r0-r4}\n"
        //"ldr    pc, [pc, #4]\n"
        "blx    print_log\n"
        //"pop    {lr}\n"
        "add    sp, sp, #4\n"
        "push   {r0}\n"
        //"ldr    r0, [sp, #-4]\n"

        "save_r5:\n"
             ".word 0x0\n"
         "save_lr:\n"
             ".word 0x0\n"
    );
    */

    return 1;
}

const int test=0x999999;

int init_func(char * str){
    LOGD("%s, hook in pid = %d\n", str, getpid());

    long target_addr = 0;

    //if target func is thumb, be sure to add 0x1 to the func addr.
    //target_addr = 0x22138; //strcmp;
    //target_addr = 0x20e78; //nanosleep;
    target_addr = 0x2dfcf; //sleep;
    //target_addr = 0x20afc; //lstat;
    hook_by_addr(&eph, "libc.so", target_addr, hook_thumb, hook_arm);
    LOGD("const addr %0x\n", &test);
    
    //hook_by_name(&eph_sendto, "libc.so", "sendto", sendto_thumb, sendto_arm);

    return 0;
}
    
