#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  // msg.sadb_msg_version =
  // msg.sadb_msg_type =
  // msg.sadb_msg_satype =
  // msg.sadb_msg_len =
  // msg.sadb_msg_pid =

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information

  // TODO: Set size to number of bytes in response message
  int size = sizeof(sadb_msg);

  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    // config.spi = 0x00000000;
    // config.aalg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    // Have enc algorithm:
    //   config.ealg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    // No enc algorithm:
    //   config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    // Source address:
    //   config.local = ipToString(ADDR);
    // Destination address:
    //   config.remote = ipToString(ADDR);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
