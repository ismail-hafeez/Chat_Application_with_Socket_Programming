/* udp_server.cpp
 *
 * UDP Chat Server (C++) with Registration, Authentication, and Menu Commands
 * 
 * Features:
 * - REGISTER / AUTH user accounts (stored in users.txt)
 * - Broadcast & private messaging
 * - File transfer (Base64 over UDP)
 * - Automatic status updates: online/away
 * - Logging + terminal display
 *
 * Compile:
 *   g++ udp_server.cpp -o udp_server
 *
 * Run:
 *   ./udp_server
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define PORT 9090
#define BUFFER_SIZE 4096
#define LOG_FILE "udp_server.log"
#define USERS_FILE "users.txt"

struct User {
    std::string username;
    std::string password;
    sockaddr_in addr;
    bool online = false;
    std::string status = "away";
};

std::map<std::string, User> users; // username -> user info

// Utility
std::string now_timestamp() {
    time_t t = time(nullptr);
    tm *tm_info = localtime(&t);
    std::ostringstream ss;
    ss << std::put_time(tm_info, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void append_log(const std::string &line) {
    std::cout << "[" << now_timestamp() << "] " << line << std::endl;
    std::ofstream ofs(LOG_FILE, std::ios::app);
    ofs << "[" << now_timestamp() << "] " << line << std::endl;
}

void send_msg(int sockfd, const std::string &msg, const sockaddr_in &addr) {
    sendto(sockfd, msg.c_str(), msg.size(), 0, (sockaddr *)&addr, sizeof(addr));
}

void broadcast_msg(int sockfd, const std::string &msg, const std::string &exclude = "") {
    for (auto &p : users) {
        if (p.second.online && p.first != exclude)
            send_msg(sockfd, msg, p.second.addr);
    }
}

void load_users() {
    std::ifstream ifs(USERS_FILE);
    if (!ifs.is_open()) return;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        size_t pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string u = line.substr(0, pos);
        std::string p = line.substr(pos + 1);
        users[u].username = u;
        users[u].password = p;
    }
}

void save_user(const std::string &username, const std::string &password) {
    std::ofstream ofs(USERS_FILE, std::ios::app);
    ofs << username << ":" << password << std::endl;
    ofs.close();
}

// ---------------- Main Server ----------------
int main() {
    int sockfd;
    sockaddr_in server_addr{}, client_addr{};
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    append_log("UDP Server started on port " + std::to_string(PORT));
    load_users();

    while (true) {
        socklen_t addrlen = sizeof(client_addr);
        ssize_t bytes = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                                 (sockaddr *)&client_addr, &addrlen);
        if (bytes <= 0) continue;
        buffer[bytes] = '\0';
        std::string msg(buffer);
        std::istringstream iss(msg);
        std::string cmd;
        iss >> cmd;

        if (cmd == "REGISTER") {
            std::string username, password;
            iss >> username >> password;
            if (username.empty() || password.empty()) {
                send_msg(sockfd, "ERROR Missing username or password", client_addr);
                continue;
            }
            if (users.count(username)) {
                send_msg(sockfd, "ERROR Username already exists", client_addr);
                continue;
            }
            save_user(username, password);
            users[username].username = username;
            users[username].password = password;
            append_log("User registered: " + username);
            send_msg(sockfd, "REGISTER_OK Please AUTH to login.", client_addr);
            continue;
        }

        if (cmd == "AUTH") {
            std::string username, password;
            iss >> username >> password;
            if (!users.count(username) || users[username].password != password) {
                send_msg(sockfd, "ERROR Invalid credentials", client_addr);
                continue;
            }
            users[username].online = true;
            users[username].addr = client_addr;
            users[username].status = "online";
            append_log(username + " logged in");
            send_msg(sockfd, "AUTH_OK Welcome " + username, client_addr);
            broadcast_msg(sockfd, "NOTIFY " + username + " joined", username);
            send_msg(sockfd, "MENU Commands: /msg <user> <text>, /file <user> <filename>, /status <s>, /history <n>, /help, /exit", client_addr);
            continue;
        }

        if (cmd == "MSG") {
            std::string sender;
            iss >> sender;
            std::string text;
            std::getline(iss, text);
            broadcast_msg(sockfd, sender + ":" + text, sender);
            append_log("MSG " + sender + ":" + text);
            continue;
        }

        if (cmd == "PRIV") {
            std::string sender, target;
            iss >> sender >> target;
            std::string text;
            std::getline(iss, text);
            if (!users.count(target) || !users[target].online) {
                send_msg(sockfd, "ERROR User not online", client_addr);
                continue;
            }
            send_msg(sockfd, "PRIVATE from " + sender + ":" + text, users[target].addr);
            append_log("PRIV " + sender + " -> " + target + ":" + text);
            continue;
        }

        if (cmd == "STATUS") {
            std::string username, status;
            iss >> username >> status;
            users[username].status = status;
            broadcast_msg(sockfd, "STATUS " + username + " " + status, username);
            append_log("STATUS " + username + " -> " + status);
            continue;
        }

        if (cmd == "LEAVE") {
            std::string username;
            iss >> username;
            if (users.count(username)) {
                users[username].online = false;
                users[username].status = "away";
                broadcast_msg(sockfd, "NOTIFY " + username + " left");
                append_log(username + " left the chat");
            }
            continue;
        }

        if (cmd == "FILE") {
            std::string sender, target, filename;
            long long size;
            iss >> sender >> target >> filename >> size;
            std::string payload;
            std::getline(iss, payload);
            if (!users.count(target) || !users[target].online) {
                send_msg(sockfd, "ERROR Target not online", client_addr);
                continue;
            }
            std::ostringstream hdr;
            hdr << "FILE " << sender << " " << filename << " " << size;
            send_msg(sockfd, hdr.str(), users[target].addr);
            send_msg(sockfd, payload, users[target].addr);
            append_log("FILE " + sender + " -> " + target + " : " + filename);
            continue;
        }
    }

    close(sockfd);
    return 0;
}
