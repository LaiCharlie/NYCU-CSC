#include <stdio.h>
#include <stdlib.h>
void purchase(int price, int your_money) {
    int amount;
    puts("Input the amount:");
    scanf("%d", &amount);
    if(amount > 0){
        int total_price = price*amount;
        if(your_money >= total_price){
            your_money -= total_price;
            printf("You have purchased the flag\n");
            getFlag();
        }
        else {
            puts("You don't have enough money!");
        }
    }
    else{
        puts("Invalid amount!");    
    }
}


void getFlag() {
    puts(getenv("FLAG"));
}

int main(int argc, char **argv){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    int flag_price = 999999, your_money = 10, choice;
    puts("Welcome to the server:");
    while(1) {
        printf("Current money: %d\n", your_money);
        puts("1. Purchase Flag");
        puts("2. Exit");
        puts("Input your choice:");
        scanf("%d", &choice);
        switch(choice) {
            case 1:
                purchase(flag_price, your_money);
                break;
            case 2:
                exit(0);
            default:
                puts("Invalid choice!");
                break;
        }
    }
}

