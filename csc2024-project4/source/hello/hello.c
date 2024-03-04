#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char name[0x20] = "user";

void init(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int read_int(){
    char buf[0x10];
    read(0, buf, 0x10);
    return atoi(buf);
}

void hello() {
    puts("Hello, Hello, Hello~~~");
}

void editName(){
    char input[0x20];
    char y = '\0';
    while (1){
        puts("Enter your new name");
        write(1, "> ", 2);
        read(0, input, 0x80);
        printf("Set fans name to %s (Y/N)\n", input);
        y = getchar();
        if (y == 'Y' || y == 'y'){
            break;
        }
    }
    strcpy(name, input);
    puts("Name changed!");
}

int main(){
    init();
    puts("Welcome to the hello server, try to get the flag!\n");

    int choice = 0;
    while (1){
        puts("1. Edit Name");
        puts("2. Say Hello");
        puts("3. Exit");
        puts("Input your choice:");
        choice = read_int();
        switch (choice){
        case 1:
            editName();
            break;
        case 2:
            hello();
            break;
        case 3:
            exit(0);
            break;
        default:
            puts("Invalid argument!!");
            break;
        }
    }
    return 0;
}