#include "util.h"

#include <arpa/inet.h>

namespace {
  std::string _ipToString(int afFamily, const void *addr) {
    char temp[64] = {};
    auto result = inet_ntop(afFamily, addr, temp, sizeof(temp));
    if (result == nullptr) {
      checkError(-1, "Convert IP to string failed");
    }
    return temp;
  }
}  // namespace

void checkError(int error, const char *message) {
#ifndef NDEBUG
  if (error == -1) {
    perror(message);
    exit(EXIT_FAILURE);
  }
#endif
}

std::string ipToString(uint32_t v4Addr) { return _ipToString(AF_INET, &v4Addr); }

in_addr stringToIPv4(const std::string &v4Addr) {
  in_addr addr;
  inet_pton(AF_INET, v4Addr.c_str(), &addr.s_addr);
  return addr;
}
