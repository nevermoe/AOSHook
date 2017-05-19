#include <stdio.h>
#include <string.h>

int count = 0;

void  sevenWeapons(int number)
{
    char* str = "Hello,LiBieGou!";
    printf("1%s %d\n",str,number);
    printf("2%s %d\n",str,number);
    printf("3%s %d\n",str,number);
    printf("4%s %d\n",str,number);
}

int main()
{
    while(1)
    {
        sevenWeapons(count);
        count++;
        sleep(1);
    }    
    return 0;
}

