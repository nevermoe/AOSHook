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
        "ldr    r4, %[p15]\n"
        "push   {r4}\n"
        "ldr    r4, %[p14]\n"
        "push   {r4}\n"
        "ldr    r4, %[p13]\n"
        "push   {r4}\n"
        "ldr    r4, %[p12]\n"
        "push   {r4}\n"
        "ldr    r4, %[p11]\n"
        "push   {r4}\n"
        "ldr    r4, %[p10]\n"
        "push   {r4}\n"
        "ldr    r4, %[p9]\n"
        "push   {r4}\n"
        "ldr    r4, %[p8]\n"
        "push   {r4}\n"
        "ldr    r4, %[p7]\n"
        "push   {r4}\n"
        "ldr    r4, %[p6]\n"
        "push   {r4}\n"
        "ldr    r4, %[p5]\n"
        "push   {r4}\n"
        "ldr    r4, %[p4]\n"
        "push   {r4}\n"
        "ldr    r4, %[p_eph]\n"
        //"push   {r4}\n"

        "add    r4, r4, #28\n"   //eph->store
        "blx    r4\n"

        "add    sp, sp, #48\n"  //pop all parameters
        "pop    {r0-r12, lr}\n"
        : 
        : [p_eph] "g" (eph), [p15] "g" (p15), 
        [p14] "g" (p14), [p13] "g" (p13), 
        [p12] "g" (p12), [p11] "g" (p11), 
        [p10] "g" (p10), [p9] "g" (p9), 
        [p8] "g" (p8), [p7] "g" (p7),
        [p6] "g" (p6), [p5] "g" (p5),
        [p4] "g" (p4)
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
    
    
