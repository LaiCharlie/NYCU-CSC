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
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type    = SADB_GET;
  msg.sadb_msg_satype  = SADB_SATYPE_ESP;
  msg.sadb_msg_len     = sizeof(sadb_msg) / 8;
  msg.sadb_msg_pid     = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  write(sock, &msg, sizeof(sadb_msg));
  read(sock, message.data(), message.size());

  // TODO: Set size to number of bytes in response message
  int size = message.size();

  // std::cerr << "Test modify" << std::endl;

  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    // config.spi = 0x00000000;
    config.spi  = reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_spi;

    // config.aalg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    config.aalg = std::make_unique<ESP_AALG>(reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_encrypt, reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_auth);

    // Have enc algorithm:
    //   config.ealg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    // No enc algorithm:
    //   config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    if(reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_encrypt == SADB_EALG_NONE) {
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    } 
    else {
      config.ealg = std::make_unique<ESP_EALG>(reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_encrypt, reinterpret_cast<sadb_sa*>(message.data())->sadb_sa_auth);
    }

    // Source address:
    //   config.local = ipToString(ADDR);
    // Destination address:
    //   config.remote = ipToString(ADDR);
    
    config.local  = ipToString(reinterpret_cast<iphdr*>(message.data())->saddr);
    config.remote = ipToString(reinterpret_cast<iphdr*>(message.data())->daddr);

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
