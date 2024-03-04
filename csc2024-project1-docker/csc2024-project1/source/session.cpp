#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  // addr_ll.sll_family =
  // addr_ll.sll_protocol =
  // addr_ll.sll_ifindex =
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
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  //   state.recvPacket =
  // Track current IP id
  //   state.ipId = ;
  // Call dissectESP(payload) if next protocol is ESP
  //   auto payload = buffer.last(buffer.size() - headerLength);
}

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
  // Call dissectTCP(payload) if next protocol is TCP
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  // state.tcpseq =
  // state.tcpackseq =
  // state.srcPort =
  // state.dstPort =

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  // hdr.version =
  // hdr.ihl =
  // hdr.ttl =
  // hdr.id =
  // hdr.protocol =
  // hdr.frag_off =
  // hdr.saddr =
  // hdr.daddr =
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  // hdr.tot_len =
  // hdr.check =
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  // hdr.spi =
  // hdr.seq =
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = 0;
  payloadLength += padSize;
  // ESP trailer
  // endBuffer[padSize] =
  // endBuffer[padSize + 1] =
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    // auto result = config.aalg->hash();
    // std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    // payloadLength += result.size();
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  // hdr.ack =
  // hdr.doff =
  // hdr.dest =
  // hdr.source =
  // hdr.ack_seq =
  // hdr.seq =
  // hdr.window =
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  // state.tcpseq =
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  // hdr.check =
  return payloadLength;
}
