#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

// Fill struct sockaddr_ll addr which will be used to bind the socket
Session::Session(const std::string& iface, ESPConfig&& cfg) : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};

  addr_ll.sll_family   = AF_PACKET;                    
  addr_ll.sll_protocol = htons(ETH_P_ALL);             
  addr_ll.sll_ifindex  = if_nametoindex(iface.c_str());

  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } 
      else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0, reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) {
          encapsulate("");
        }
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

// struct State {
//   uint32_t espseq;
//   uint32_t tcpseq;
//   uint32_t tcpackseq;
//   uint16_t srcPort;
//   uint16_t dstPort;
//   uint16_t ipId;
//   bool sendAck;
//   bool recvPacket;
// };

// ----------------- Dissection -----------------
// Set payload
void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote

  // auto&& hdr  = *reinterpret_cast<iphdr*>(payload.data());
  // std::cout << "src IP: " << inet_ntoa(*(in_addr*)&hdr.saddr) << std::endl;
  // std::cout << "dst IP: " << inet_ntoa(*(in_addr*)&hdr.daddr) << std::endl << std::endl;
  dissectIPv4(payload);
}

/*
struct iphdr { 
  #if defined(__LITTLE_ENDIAN_BITFIELD) 
    __u8 ihl:4, version:4; 
  #elif defined (__BIG_ENDIAN_BITFIELD) 
    __u8 version:4, ihl:4; 
  #else #error "Please fix <asm/byteorder.h>" 
  #endif 
    __u8 tos; 
    __be16 -tot_len; 
    __be16 - id;
    __be16 - frag_off; 
    __u8 ttl; 
    __u8 protocol; 
    __be16 - check; 
    __be32 - saddr; 
    __be32 - daddr; 
  };
*/

// Extract IPv4 header and payload, and check if receiving packet from remote
void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  //   state.recvPacket =
  if(inet_ntoa(*(in_addr*)&hdr.saddr) == config.remote)
    state.recvPacket = true;
  else
    state.recvPacket = false;

  // Track current IP id
  //   state.ipId = ;
  if (!state.recvPacket)
    state.ipId = htons(hdr.id);

  // Call dissectESP(payload) if next protocol is ESP
  if(hdr.protocol == IPPROTO_ESP) {
    auto payload = buffer.last(buffer.size() - hdr.ihl * 4);
    dissectESP(payload);
  }
}

/*
buffer:
      -----------------------------------
ESP   | ESP |     |      |   ESP   | ESP|
      | Hdr | TCP | Data | Trailer |Auth|
      -----------------------------------
            |<----- encrypted ---->|
      |<------ authenticated ----->|
*/

// Extract ESP header and payload, and track ESP sequence number
void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }
  
  // TODO:
  // Track ESP sequence number
  //   state.espseq = ;
  if (!state.recvPacket)
    state.espseq = ntohl(hdr.seq);

  auto    tail_buffer   = buffer.last(sizeof(ESPTrailer));
  uint8_t next_protocol = reinterpret_cast<ESPTrailer*>(tail_buffer.data())->next;
  int     padlen        = reinterpret_cast<ESPTrailer*>(tail_buffer.data())->padlen;

  // Call dissectTCP(payload) if next protocol is TCP
  if(next_protocol == IPPROTO_TCP) {
    auto payload = buffer.first(buffer.size() - sizeof(ESPTrailer) - padlen);
    dissectTCP(payload);
  }
}

// Extract TCP header, and track TCP header parameters
void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr   = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length  = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  if (!state.recvPacket) {
    state.tcpseq     = ntohl(hdr.seq);
    state.tcpackseq  = ntohl(hdr.ack_seq);
    state.srcPort    = ntohs(hdr.source);
    state.dstPort    = ntohs(hdr.dest);
  }
  else {
    state.tcpseq     = ntohl(hdr.ack_seq);
    state.tcpackseq  = ntohl(hdr.seq) + payload.size();
  }

  // Is ACK message?
  if (payload.empty())
    return;
  
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
    // std::cout << "hdr.ack_seq   = " << ntohl(hdr.ack_seq) << std::endl;
    // std::cout << "hdr.tcp_seq   = " << ntohl(hdr.seq)     << std::endl;
    // std::cout << "payload.size  = " << payload.size()     << std::endl;
    // std::cout << "state.ack_seq = " << state.tcpackseq    << std::endl;
    // std::cout << "state.tcp_seq = " << state.tcpseq       << std::endl << std::endl;
  }
}

// ----------------- Encapsulation -----------------

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);

  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

/*
struct iphdr { 
  #if defined(__LITTLE_ENDIAN_BITFIELD) 
    __u8 ihl:4, version:4; 
  #elif defined (__BIG_ENDIAN_BITFIELD) 
    __u8 version:4, ihl:4; 
  #else #error "Please fix <asm/byteorder.h>" 
  #endif 
    __u8 tos; 
    __be16 -tot_len; 
    __be16 - id;
    __be16 - frag_off; 
    __u8 ttl; 
    __u8 protocol; 
    __be16 - check; 
    __be32 - saddr; 
    __be32 - daddr; 
  };
*/

uint16_t calculateIpChecksum(const struct iphdr* ipHeader) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(ipHeader);
    int length = ipHeader->ihl * 4;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}
/*
      -------------------------------------------------
IPv4  |orig IP hdr  | ESP |     |      |   ESP   | ESP|
      |(any options)| Hdr | TCP | Data | Trailer |Auth|
      -------------------------------------------------
                          |<----- encrypted ---->|
                    |<------ authenticated ----->|
*/

// Fill IPv4 header, and compute the checksum
int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version  = 4;
  hdr.ihl      = sizeof(iphdr) / 4;
  hdr.ttl      = 64;
  hdr.id       = htons(state.ipId);
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(16384);
  hdr.saddr    = inet_addr(config.local.c_str());
  hdr.daddr    = inet_addr(config.remote.c_str());

  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  hdr.check   = calculateIpChecksum(&hdr);

  return payloadLength;
}

/*
buffer:
      -----------------------------------
ESP   | ESP |     |      |   ESP   | ESP|
      | Hdr | TCP | Data | Trailer |Auth|
      -----------------------------------
            |<----- encrypted ---->|
      |<------ authenticated ----->|
*/

/*
struct ESPTrailer {
  uint8_t padlen;
  uint8_t next;
};
*/

// Fill ESP header, padding, and HMAC parameters
int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr      = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));    // should = TCP_hdr + Data + padding + ESP Trailer + ESP Auth
  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(++state.espseq);

  int payloadLength = encapsulateTCP(nextBuffer, payload);             // TCP_hdr + Data

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength); // padding + ESP Trailer+ ESP Auth
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = 0;
  padSize = (8 - ((payloadLength % 4) + 2)) % 4;
  for (int i = 0; i < padSize; i++) {
    endBuffer[i] = i + 1;
  }

  // ESP trailer
  endBuffer[padSize]     = padSize;     // padlen
  endBuffer[padSize + 1] = IPPROTO_TCP; // next protocol (TCP)

  payloadLength += padSize;
  payloadLength += sizeof(ESPTrailer);                                 // TCP_hdr + Data + padding + ESP Trailer
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  // ESP authentication
  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(std::span<uint8_t>(buffer.first(payloadLength)));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

/* set tcp checksum: given IP header and tcp segment */
void tcp_checksum(struct PseudoIPv4Header *pIph, unsigned short *ipPayload, uint16_t tcpLen) {
    uint32_t sum = 0;
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header
    sum += (pIph->src>>16)&0xFFFF;
    sum += (pIph->src)&0xFFFF;
    sum += (pIph->dst>>16)&0xFFFF;
    sum += (pIph->dst)&0xFFFF;

    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
 
    // initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }

    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;

    tcphdrp->check = (unsigned short)sum;
}


/*
struct State {
  uint32_t espseq;
  uint32_t tcpseq;
  uint32_t tcpackseq;
  uint16_t srcPort;
  uint16_t dstPort;
  uint16_t ipId;
  bool sendAck;
  bool recvPacket;
};
*/

/*
buffer:
    --------------
TCP |     |      |
    | TCP | Data |
    --------------
*/

// Fill TCP header, and compute the checksum
int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack     = 1;
  hdr.doff    = sizeof(tcphdr) / 4;
  hdr.dest    = htons(state.dstPort);
  hdr.source  = htons(state.srcPort);

  hdr.ack_seq = htonl(state.tcpackseq);
  hdr.seq     = htonl(state.tcpseq);
  hdr.window  = htons(512);             // desired window size

  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  // state.tcpseq =
  state.tcpseq = state.tcpseq + payload.size();

  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  // hdr.check =
  PseudoIPv4Header* phdr = (PseudoIPv4Header*)malloc(sizeof(PseudoIPv4Header));
  phdr -> src = inet_addr(config.local.c_str());
  phdr -> dst = inet_addr(config.remote.c_str());
  phdr -> zero = 0;
  phdr -> protocol = IPPROTO_TCP;
  phdr -> length = payloadLength;
  uint16_t* checksumbuffer = (uint16_t*)malloc((sizeof(PseudoIPv4Header) + payloadLength));
  memcpy(checksumbuffer, phdr, sizeof(PseudoIPv4Header));
  memcpy(checksumbuffer + sizeof(PseudoIPv4Header), buffer.data(), payloadLength);

  tcp_checksum(phdr, (unsigned short*)buffer.data(), payloadLength);

  return payloadLength;
}

/*
struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
*/

// (ip.src == 172.18.1.1 && ip.dst == 172.18.100.254) || (ip.dst == 172.18.1.1 && ip.src == 172.18.100.254)
