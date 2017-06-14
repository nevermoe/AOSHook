#include <stdio.h>
#include "hook.h"

void pre_hook_arm(int p0, int p1, int p2, int p3, int r0, int r1, int r2, int r3, int lr, int eph)
{
    LOGD("pre_hook_arm\n");
    struct hook_t* ctx = (struct hook_t*)eph;
    LOGD("eph addr: 0x%x    0x%x    0x%x    0x%x    0x%x    0x%x    0x%x    0x%x    0x%x    0x%x\n", p0, p1, p2, p3, r0, r1, r2, r3, lr, eph);
    LOGD("func 0x%x call begin.\n", (unsigned int)(ctx->orig - ctx->module_base));
    LOGD("store addr: 0x%x .\n", (unsigned int)(ctx->store));
}

void post_hook_arm(int p0, int p1, int p2, int p3, int r0, int r1, int r2, int r3, int lr, int eph)
{
    LOGD("post_hook_arm\n");
    struct hook_t* ctx = (struct hook_t*)eph;
    LOGD("func 0x%x call end.\n", (unsigned int)(ctx->orig - ctx->module_base));
}

__attribute__((naked)) int hook_arm(int p0,int p1,int p2,int p3,int eph, int p4, int p5, int p6, int p7, int p8, int p9, int p10, int p11, int p12, int p13, int p14, int p15)
{
    //pre_hook_arm(p0, p1, p2, p3, p4, p5, p6, p7, p8, eph);
    //call pre_hook_arm
    __asm __volatile (
        "push   {r0-r3, lr}\n"
        "bl     pre_hook_arm\n"
        "pop    {r0-r3, lr}\n"
    );


    //call orig function
    __asm __volatile (
        "push   {r0-r12, lr}\n"
        "ldr    r4, [sp, #104]\n" //p15
        "str    r4, [sp, #-4]\n"
        "ldr    r4, [sp, #100]\n" //p14
        "str    r4, [sp, #-8]\n"
        "ldr    r4, [sp, #96]\n" //p13
        "str    r4, [sp, #-12]\n"
        "ldr    r4, [sp, #92]\n" //p12
        "str    r4, [sp, #-16]\n"
        "ldr    r4, [sp, #88]\n" //p11
        "str    r4, [sp, #-20]\n"
        "ldr    r4, [sp, #84]\n" //p10
        "str    r4, [sp, #-24]\n"
        "ldr    r4, [sp, #80]\n" //p9
        "str    r4, [sp, #-28]\n"
        "ldr    r4, [sp, #76]\n" //p8
        "str    r4, [sp, #-32]\n"
        "ldr    r4, [sp, #72]\n" //p7
        "str    r4, [sp, #-36]\n"
        "ldr    r4, [sp, #68]\n" //p6
        "str    r4, [sp, #-40]\n"
        "ldr    r4, [sp, #64]\n" //p5
        "str    r4, [sp, #-44]\n"
        "ldr    r4, [sp, #60]\n" //p4, sp+14*4+4
        "str    r4, [sp, #-48]\n"

        "ldr    r4, [sp, #56]\n" //eph
        "ldr    r5, [r4, #144]\n"   //eph->thumb

        "sub    sp, sp, #48\n"  //make sp at top of 12 params

        "cmp    r5, #0\n"   //if is arm mode
        "beq    arm_mode\n"

        "thumb_mode:\n"
            "add    r4, r4, #93\n"   //eph->storet+1
            "b      call_orig\n"

        "arm_mode:\n"
            "add    r4, r4, #28\n"   //eph->store
            "b      call_orig\n"

        "call_orig:\n"
            "blx    r4\n"

        "add    sp, sp, #48\n"  //pop all parameters (p4~p15)
        "pop    {r0-r12, lr}\n"
    );

    //call post_hook_arm
    __asm __volatile (
        "push   {r0-r3, lr}\n"
        "bl     post_hook_arm\n"
        "pop    {r0-r3, lr}\n"
        "add    sp, sp, #4\n"   //pop eph
        "bx     lr\n"   //return
    );
}
    
    
