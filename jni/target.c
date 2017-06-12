#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

int count = 0;

void test1(int number)
{
    char* str = "HelloW0rld!";
    printf("1 %s %d\n",str,number);
    printf("2 %s %d\n",str,number);
}

void test2(char* str)
{
    char* str2 = "HelloW0rld!";
    printf("cmp result: %d\n",strcmp(str, str2));
}

int main()
{
    volatile int i = 0;
    //scanf("%d", &i);
    //char fname[40];
    struct stat buf;
    while(1)
    {
        //test2("null");
        i++;
        sleep(1);
        //sprintf(fname, "test.%d", i)+
        //rename("test.1", fname);
        lstat("/data/local/tmp/test", &buf);
        printf("%lld\n", buf.st_size);
    }    
    return 0;
}

