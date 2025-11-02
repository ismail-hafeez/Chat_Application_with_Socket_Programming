/* udp_client.cpp
 * UDP Chat Client (C++) with Register, Auth, and Menu Commands
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#define SERVER_IP "127.0.0.1"
#define PORT 9090
#define BUFFER_SIZE 4096

std::atomic<bool> running(true);
int sockfd;
sockaddr_in server_addr{};
std::string username;

// Receiver thread
void receive_thread() {
    char buffer[BUFFER_SIZE];
    sockaddr_in from_addr{};
    socklen_t addrlen = sizeof(from_addr);
    while (running) {
        ssize_t bytes = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                                 (sockaddr *)&from_addr, &addrlen);
        if (bytes <= 0) continue;
        buffer[bytes] = '\0';
        std::cout << "\n" << buffer << "\n> " << std::flush;
    }
}

int main() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    std::thread recv_t(receive_thread);

    std::cout << "Connected to UDP server.\n";
    while (true) {
        std::cout << "Choose: (1) AUTH  (2) REGISTER : ";
        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "1" || choice == "AUTH") {
            std::string password;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Password: ";
            std::getline(std::cin, password);
            std::string msg = "AUTH " + username + " " + password;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
            break;
        } else if (choice == "2" || choice == "REGISTER") {
            std::string u, p;
            std::cout << "Choose username: ";
            std::getline(std::cin, u);
            std::cout << "Choose password: ";
            std::getline(std::cin, p);
            std::string msg = "REGISTER " + u + " " + p;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
        }
    }

    while (running) {
        std::cout << "> ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        if (line.rfind("/msg ", 0) == 0) {
            std::istringstream iss(line);
            std::string cmd, target;
            iss >> cmd >> target;
            std::string text;
            std::getline(iss, text);
            std::string msg = "PRIV " + username + " " + target + " " + text;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
        } else if (line.rfind("/status ", 0) == 0) {
            std::istringstream iss(line);
            std::string cmd, status;
            iss >> cmd >> status;
            std::string msg = "STATUS " + username + " " + status;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
        } else if (line == "/help") {
            std::cout << "MENU Commands: /msg <user> <text>, /file <user> <filename>, /status <s>, /history <n>, /help, /exit\n";
        } else if (line == "/exit") {
            std::string msg = "LEAVE " + username;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
            running = false;
            break;
        } else {
            std::string msg = "MSG " + username + " " + line;
            sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&server_addr, sizeof(server_addr));
        }
    }

    running = false;
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    if (recv_t.joinable()) recv_t.join();
    std::cout << "Goodbye!\n";
    return 0;
}
