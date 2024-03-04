#include <arpa/inet.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <cxxopts.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include "util.h"

bool running = true;

std::unordered_map<std::string, std::string> initAnswer(const std::string &filename) {
  std::unordered_map<std::string, std::string> flags;
  std::ifstream file(filename);
  if (!file) {
    std::cerr << "[Error] File read failed \n";
    exit(1);
  }

  std::string key;

  while (std::getline(file, key, ':')) {
    std::getline(file, flags[key]);
  }
  return flags;
}

void handleSocket(int sockfd, const std::unordered_map<std::string, std::string> &flags) {
  char recvBuffer[4096] = {};
  ssize_t recvcnt = recv(sockfd, recvBuffer, sizeof(recvBuffer), 0);
  if (recvcnt < 0) {
    checkError(recvcnt, "Recv error");
  } else if (recvcnt == 0) {
    std::cerr << "Connection closed by client\n";
    close(sockfd);
  } else {
    std::cout << recvBuffer;
    recvBuffer[strcspn(recvBuffer, "\r\n")] = 0;
    if (auto it = flags.find(recvBuffer); it != flags.end()) {
      std::cout << "[Info] "
                << "Get correct answer " << it->second << std::endl;
      send(sockfd, it->second.data(), it->second.size(), 0);
    }
  }
}

int main(int argc, char *argv[]) {
  cxxopts::Options options("client", "A simple TCP client");
  // clang-format off
  options.add_options()
  ("p,port", "Server Port", cxxopts::value<int>())
  ("f,file", "Answer file", cxxopts::value<std::string>()->default_value("scripts/answer.txt"))
  ("h,help", "Show help message");
  // clang-format on
  options.parse_positional({"port"});
  options.positional_help("[server port]");

  cxxopts::ParseResult result = options.parse(argc, argv);
  if (argc < 2 || result.count("help")) {
    std::cout << options.help() << std::endl;
    return 1;
  }
  struct sigaction action {};
  action.sa_handler = [](int) { running = false; };
  sigaction(SIGINT, &action, nullptr);
  auto flags = initAnswer(result["file"].as<std::string>());

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  checkError(sockfd, "Open socket");

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(result["port"].as<int>());
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  constexpr int enable = 1;
  checkError(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)),
             "Set reuse address");
  checkError(bind(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr_in)), "bind");

  listen(sockfd, 4);

  epoll_event triggeredEvent[10];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sockfd;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sockfd, &event), "Failed to add sock to epoll");

  // Accpet from client
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 10, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        running = false;
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
        }
      } else if (triggeredEvent[i].data.fd == sockfd) {
        int clientfd = accept(sockfd, nullptr, nullptr);
        if (clientfd != -1) {
          event.data.fd = clientfd;
          checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, clientfd, &event),
                     "Failed to add sock to epoll");
        }
      } else {
        handleSocket(triggeredEvent[i].data.fd, flags);
      }
    }
  }
  close(sockfd);
}
