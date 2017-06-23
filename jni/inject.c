
#include "hook.h"
#include <android/log.h>

//0 = NOT STALKING
//1 = STALKING
int ISSTALKING = 1;

static struct hook_t eph_sendto;
static struct hook_t eph_recvfrom;


static struct hook_t eph1;
    


int hook_func1(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19);
	orig_func = (void*)eph1.proto;
    
    if (ISSTALKING)
        LOGD("func 0x%x call begin.\n", (unsigned int)(eph1.target_addr-eph1.module_base));

	int ret = orig_func(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19);

    if (ISSTALKING)
        LOGD("func 0x%x call end.\n", (unsigned int)(eph1.target_addr-eph1.module_base));

    return ret;
}
    

int hook_recvfrom(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19);
	orig_func = (void*)eph_recvfrom.proto;
    
    LOGD("STALKING START at 0x%x\n", (unsigned int)(eph_recvfrom.target_addr-eph_recvfrom.module_base));
    ISSTALKING = 1;

	int ret = orig_func(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19);

    return ret;
}

int hook_sendto(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5,int p6,int p7,int p8,int p9,int p10,int p11,int p12,int p13,int p14,int p15,int p16,int p17,int p18,int p19);
	orig_func = (void*)eph_sendto.proto;
    
    LOGD("STALKING END at 0x%x\n", (unsigned int)(eph_sendto.target_addr-eph_sendto.module_base));
    ISSTALKING = 0;

	int ret = orig_func(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19);

    return ret;
}

int init_func(char * str){
    LOGD("%s, hook in pid = %d\n", str, getpid());

    long target_addr = 0;

    
    target_addr = 0x2a9085;
    hook_by_addr(&eph1, "libclient.so", target_addr, hook_func1);
    

    hook_by_name(&eph_sendto, "libc.so", "sendto", hook_sendto);
    hook_by_name(&eph_recvfrom, "libc.so", "recvfrom", hook_recvfrom);

    return 0;
}
    