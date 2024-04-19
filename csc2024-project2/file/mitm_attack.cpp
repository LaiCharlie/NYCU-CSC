#include <iostream>
#include <cstring>
#include <map>
#include <iomanip>
#include <string>
#include <vector>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netdb.h>
#include <thread>

using namespace std;

/*
struct ether_hdr {
   uint8_t  dest_addr[ETH_ALEN];   // Destination hardware address
   uint8_t  src_addr[ETH_ALEN];    // Source hardware address
   uint16_t frame_type;            // Ethernet frame type
};

struct ether_arp {
   uint16_t  htype;          // Format of hardware address
   uint16_t  ptype;          // Format of protocol address
   uint8_t   hlen;           // Length of hardware address
   uint8_t   plen;           // Length of protocol address
   uint16_t  op;             // ARP opcode command
   uint8_t   sha[ETH_ALEN];  // Sender hardware address
   uint32_t  spa;            // Sender protocol address
   uint8_t   tha[ETH_ALEN];  // Target hardware address
   uint32_t  tpa;            // Target protocol address
};
*/

struct ownaddr {
    string ip;
    string mac;
};

map<string, string> seen_addresses;
string default_gateway = "";
ownaddr own;

void get_hostip() {
    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        std::cout << "Socket error" << std::endl;
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_server);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr*)&serv, sizeof(serv));
    if (err < 0) {
        std::cout << "Error number: " << errno << ". Error message: " << strerror(errno) << std::endl;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*)&name, &namelen);

    char buffer[80];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 80);
    if(p != NULL) 
        own.ip = string(buffer);

    close(sock);
}

void get_defaultgw() {
    FILE *f;
    char line[100] , *p , *c, *g, *saveptr;
    f = fopen("/proc/net/route", "r");

    while(fgets(line , 100 , f)) {
        p = strtok_r(line, " \t", &saveptr);
        c = strtok_r(NULL, " \t", &saveptr);
        g = strtok_r(NULL, " \t", &saveptr);

        if(p != NULL && c != NULL) {
            if(strcmp(c, "00000000") == 0) {
                if(g) {
                    char *pEnd;
                    int ng = strtol(g, &pEnd,16);
                    struct in_addr addr;
                    addr.s_addr = ng;
                    default_gateway = string(inet_ntoa(addr));
                }
                break;
            }
        }
    }
    fclose(f);
    return;
}

void read_arp_table() {
    FILE* arp_file = fopen("/proc/net/arp", "r");
    if (!arp_file) {
        throw runtime_error("Failed to open /proc/net/arp");
    }

    char line[256];
    fgets(line, sizeof(line), arp_file);

    while (fgets(line, sizeof(line), arp_file)) {
        char ip_str[16], hw_type[6], flags[6], mac_str[18], mask_str[6], device[500];
        int n = sscanf(line, "%s 0x%s 0x%s %17s %s %s", ip_str, hw_type, flags, mac_str, mask_str, device);
        if (n == 6) {
            string ip_address(ip_str);
            string mac_address(mac_str);
            string nmask(mask_str);

            if (ip_address != own.ip) 
                seen_addresses[ip_address] = mac_address;
            else
                own.mac = mac_address;
        }
    }

    fclose(arp_file);
}

void arp_lookup() {
    int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Socket creation failed");
        return;
    }

    unsigned char buffer[1024];
    while (true) {
        ssize_t bytes_received = recv(raw_socket, buffer, sizeof(buffer), 0);

        if (bytes_received >= 42) {
            if (buffer[12] == 0x08 && buffer[13] == 0x06) {
                string sender_mac = "";
                string sender_ip  = "";
                string own_mac    = "";
                string own_ip     = "";

                for (int i = 0; i < 6; i++) {
                    char mac_byte[3];
                    sprintf(mac_byte, "%02X", buffer[i + 22]);
                    sender_mac += mac_byte;
                    if (i < 5) sender_mac += ":";
                }

                for (int i = 0; i < 4; i++) {
                    sender_ip += to_string(buffer[i + 28]);
                    if (i < 3) sender_ip += ".";
                }

                for (int i = 0; i < 6; i++) {
                    char mac_byte[3];
                    sprintf(mac_byte, "%02X", buffer[i + 32]);
                    own_mac += mac_byte;
                    if (i < 5) own_mac += ":";
                }

                for (int i = 0; i < 4; i++) {
                    own_ip += to_string(buffer[i + 38]);
                    if (i < 3) own_ip += ".";
                }
                own.ip  = own_ip;
                own.mac = own_mac;

                if (seen_addresses.find(sender_ip) == seen_addresses.end()){
                    seen_addresses[sender_ip] = sender_mac;
                    cout << "IP:  " << sender_ip  << "\n";
                    cout << "MAC: " << sender_mac << "\n";
                }
            }
        }
        if(seen_addresses.size() > 2) break;
    }

    close(raw_socket);
}

int main() {
    struct timeval start, end;
    gettimeofday(&start, 0);

    get_hostip();
    get_defaultgw();
    read_arp_table();

    cout << "Available devices\n";
    cout << "-----------------------------------------\n";
    cout << "IP                 MAC\n";
    for (auto it = seen_addresses.begin(); it != seen_addresses.end(); it++)
        cout << left << setw(12) << it->first << "       " << it->second << '\n';
    cout << "-----------------------------------------\n";



    gettimeofday(&end, 0);
    cout << "time: " << (end.tv_sec  - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0 << " s\n";

    return 0;
}