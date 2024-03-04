#include <iostream>
#include <ctime>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

std::string generate_secret() {
    srand(time(0));
    std::string secret;
    for (int i = 0; i < 16; i++) {
        secret += char(48 + (rand() % (126 - 47) + 1));
    }
    return secret;
}

int main() {
    const char* server_ip = "140.113.24.241";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(30171);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return -1;
    }
    std::string secret = generate_secret();

    char buffer[4096];
    memset(buffer, '\0', 4096);
    read(sock, buffer, 4096);

    send(sock, secret.c_str(), secret.length(), 0);
    // std::cout << secret << '\n';

    memset(buffer, '\0', 4096);
    read(sock, buffer, 4096);
    std::cout << buffer << "\n";

    close(sock);

    return 0;
}