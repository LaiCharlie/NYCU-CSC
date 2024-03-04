CC=g++
CFLAGS=-Wall -Wextra -std=c++11

all: mitm_attack pharm_attack
	 echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
	 echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects

mitm_attack: mitm_attack.cpp
	sudo $(CC) $(CFLAGS) -o mitm_attack mitm_attack.cpp -lpthread -lnetfilter_queue -w

pharm_attack: pharm_attack.cpp
	sudo $(CC) $(CFLAGS) -o pharm_attack pharm_attack.cpp -lpthread -lnetfilter_queue -w

clean:
	sudo rm -f mitm_attack pharm_attack
