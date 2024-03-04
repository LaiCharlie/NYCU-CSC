#pragma once
#include <linux/pfkeyv2.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include "encoder.h"
#include "util.h"

struct ESPConfig {
  // For ESP Header
  uint32_t spi;
  // ESP encryption
  std::unique_ptr<ESP_EALG> ealg;
  // ESP authentication
  std::unique_ptr<ESP_AALG> aalg;
  // Remote IP address
  std::string remote;
  // Local IP address
  std::string local;
  friend std::ostream& operator<<(std::ostream& os, const ESPConfig& config);
};

std::optional<ESPConfig> getConfigFromSADB();
