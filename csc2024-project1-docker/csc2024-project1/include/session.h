#pragma once
#include <linux/if_packet.h>

#include <memory>
#include <span>
#include <string>
#include <vector>

#include "encoder.h"
#include "sadb.h"
#include "util.h"

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

class Session {
public:
  Session(const std::string& iface, ESPConfig&& cfg);
  ~Session();
  void run();

private:
  void dissect(ssize_t rdcnt);
  void dissectIPv4(std::span<uint8_t> buffer);
  void dissectESP(std::span<uint8_t> buffer);
  void dissectTCP(std::span<uint8_t> buffer);

  void encapsulate(const std::string& payload);
  int encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload);
  int encapsulateESP(std::span<uint8_t> buffer, const std::string& payload);
  int encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload);

  int sock;
  sockaddr_ll addr;
  socklen_t addrLen;
  uint8_t recvBuffer[4096], sendBuffer[1024];
  ESPConfig config;
  State state;
};
