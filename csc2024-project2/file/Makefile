CC=g++
CFLAGS=-Wall -Wextra -std=c++11

all: mitm_attack pharm_attack

mitm_attack: mitm_attack.cpp
	sudo $(CC) $(CFLAGS) -o mitm_attack mitm_attack.cpp

pharm_attack: pharm_attack.cpp
	sudo $(CC) $(CFLAGS) -o pharm_attack pharm_attack.cpp

clean:
	sudo rm -f mitm_attack pharm_attack
