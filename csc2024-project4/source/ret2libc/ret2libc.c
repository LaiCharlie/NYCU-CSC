#include <stdio.h>
#include <stdlib.h>

void hackMe() {
	char buf[128];
	read(0, buf, 256);
}

int main(int argc, char **argv){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Welcome to the server!"); 
    hackMe();
    puts("Goodbye!");
}

