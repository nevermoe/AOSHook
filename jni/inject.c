#include "hook.h"
#include <android/log.h>


static struct hook_t eph_sendto;
static struct hook_t eph_recvfrom;
extern int sendto_arm(int p0,int p1,int p2,int p3,int p4,int p5);
extern int recvfrom_arm(int p0,int p1,int p2,int p3,int p4,int p5);


static struct hook_t eph1;
    
extern int hook_arm1(int p0,int p1,int p2,int p3,int p4,int p5);


int hook_thumb1(int p0,int p1,int p2,int p3,int p4,int p5)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5);
	orig_func = (void*)eph1.orig;
    
	hook_unset_jump(&eph1);

    LOGD("func 0x%x call begin.\n", (unsigned int)(orig_func - eph1.module_base));

	int ret = orig_func(p0,p1,p2,p3,p4,p5);
	hook_set_jump(&eph1);

    LOGD("func 0x%x call end.\n", (unsigned int)(orig_func - eph1.module_base));

    return ret;
}
    

int recvfrom_thumb(int p0,int p1,int p2,int p3,int p4,int p5)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5);
	orig_func = (void*)eph_recvfrom.orig;
    
	hook_unset_jump(&eph_recvfrom);

    LOGD("Calling recvfrom\n");

	int ret = orig_func(p0,p1,p2,p3,p4,p5);
	hook_set_jump(&eph_recvfrom);

    return ret;
}

int sendto_thumb(int p0,int p1,int p2,int p3,int p4,int p5)
{
	int (*orig_func)(int p0,int p1,int p2,int p3,int p4,int p5);
	orig_func = (void*)eph_sendto.orig;
    
	hook_unset_jump(&eph_sendto);

    LOGD("Calling sendto\n");

	int ret = orig_func(p0,p1,p2,p3,p4,p5);
	hook_set_jump(&eph_sendto);

    return ret;
}

int init_func(char * str){
    LOGD("%s, hook in pid = %d\n", str, getpid());

    long target_addr = 0;

    
    //if target func is thumb, be sure to add 0x1 to the func addr.
    target_addr = 0x2ca43c;
    hook_by_addr(&eph1, "libc.so", target_addr, hook_thumb1, hook_arm1);
    
    hook_by_name(&eph_sendto, "libc.so", "sendto", sendto_thumb, sendto_arm);
    hook_by_name(&eph_recvfrom, "libc.so", "recvfrom", recvfrom_thumb, recvfrom_arm);

    return 0;
}
    
