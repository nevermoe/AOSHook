#include <stdio.h>

extern int sendto_thumb(int p0,int p1,int p2,int p3,int p4,int p5);
extern int recvfrom_thumb(int p0,int p1,int p2,int p3,int p4,int p5);

int sendto_arm(int p0,int p1,int p2,int p3,int p4,int p5)
{
    return sendto_thumb(p0,p1,p2,p3,p4,p5);
}

int recvfrom_arm(int p0,int p1,int p2,int p3,int p4,int p5)
{
    return recvfrom_thumb(p0,p1,p2,p3,p4,p5);
}

extern int hook_thumb1(int p0,int p1,int p2,int p3,int p4,int p5);

int hook_arm1(int p0,int p1,int p2,int p3,int p4,int p5)
{
    return hook_thumb1(p0,p1,p2,p3,p4,p5);
}
    
    
