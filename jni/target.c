#include <stdio.h>
#include <string.h>

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
    while(1)
    {
        test2("null");
        count++;
        sleep(1);
    }    
    return 0;
}

