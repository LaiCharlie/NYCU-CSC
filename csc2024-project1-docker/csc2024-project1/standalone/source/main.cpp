#include <signal.h>
#include <unistd.h>

#include <cxxopts.hpp>
#include <iostream>
#include <string>
#include <utility>

#include "sadb.h"
#include "session.h"

bool running = true;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <if_name>\n";
    return 1;
  }
  if (geteuid() != 0) {
    std::cerr << "You need root privilege to run this application\n";
    return 1;
  }
  signal(SIGINT, [](int) { running = false; });
  std::string interface = argv[1];
  auto config = getConfigFromSADB();
  if (config) {
    std::cout << *config << std::endl;
    Session session(interface, std::move(*config));
    session.run();
  }
  return 0;
}
