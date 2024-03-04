// #include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cxxopts.hpp>
#include <iostream>
#include <thread>

#include "util.h"

bool running = true;

void bindPort(int socket, int bindPort) {
  constexpr int enable = 1;
  checkError(setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)),
             "Set reuse address");

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(bindPort);
  addr.sin_addr.s_addr = 0;

  checkError(bind(socket, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr_in)), "bind");
}

int connectTCP(const std::string &ip, int serverPort, int localPort) {
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
  addr.sin_port = htons(serverPort);

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  checkError(sockfd, "Failed to create socket");
  bindPort(sockfd, localPort);
  checkError(connect(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr_in)), "connect");
  return sockfd;
}

int main(int argc, char **argv) {
  cxxopts::Options options("client", "A simple TCP client");
  // clang-format off
  options.add_options()
  ("s,server", "Server IP", cxxopts::value<std::string>())
  ("p,port", "Server Port", cxxopts::value<int>())
  ("b,bindport", "Client bind port", cxxopts::value<int>())
  ("h,help", "Show help message");
  // clang-format on
  options.parse_positional({"server", "port", "bindport"});
  options.custom_help("");
  options.positional_help("[server ip] [server port] [bind port]");

  cxxopts::ParseResult result = options.parse(argc, argv);
  if (argc != 4 || result.count("help")) {
    std::cout << options.help() << std::endl;
    return 1;
  }
  struct sigaction action {};
  action.sa_handler = [](int) { running = false; };
  sigaction(SIGINT, &action, nullptr);
  int sockfd = 0;
  try {
    sockfd = connectTCP(result["server"].as<std::string>(), result["port"].as<int>(),
                        result["bindport"].as<int>());
  } catch (const cxxopts::exceptions::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  char sendBuffer[] = "I am client, and I am keeping sending message to server hahahaha\n";
  while (running) {
    // write msg
    ssize_t sendcnt = send(sockfd, sendBuffer, sizeof(sendBuffer) - 1, 0);
    if (sendcnt < 0) break;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  shutdown(sockfd, SHUT_RDWR);
  close(sockfd);
}
