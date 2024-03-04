#pragma once

#include <netinet/in.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <span>
#include <string>

#pragma pack(push)
#pragma pack(1)
struct ESPHeader {
  uint32_t spi;
  uint32_t seq;
};

struct ESPTrailer {
  uint8_t padlen;
  uint8_t next;
};

struct PseudoIPv4Header {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t length;
};
#pragma pack(pop)

void checkError(int error, const char *message);

std::string ipToString(uint32_t v4Addr);
in_addr stringToIPv4(const std::string &v4Addr);

struct Epoll {
  Epoll() {
    fd = epoll_create(4);
    checkError(fd, "Failed to create epoll fd");
  }
  ~Epoll() { checkError(close(fd), "Failed to close epoll fd"); }
  int fd;
};
