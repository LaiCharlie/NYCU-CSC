#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

char secret[0x10];

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(0));
    for (int i = 0; i < 0x10; i++)
    {
        secret[i] = 48 + (rand() % (126 - 47) + 1);
    }
}

int main(){
    init();
    puts("Please enter the secret: ");
    char input[0x10];
    read(0, input, 0x10);
    if (strcmp(input, secret) == 0)
    {
        puts("You got it! Here is your flag!");
        puts(getenv("FLAG"));
    }
    else
    {
        puts("Guess wrong!");
    }
    return 0;
}