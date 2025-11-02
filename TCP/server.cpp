/* server.cpp
 *
 * TCP Chat Server (C++)
 *
 * Features implemented:
 * - Multiple clients handled via select()
 * - Simple authentication (AUTH username password) with registration (REGISTER)
 * - Private messaging (/msg <user> <text>)
 * - File transfer over TCP with Base64 payload forwarding (/file <user> <path> - client-side)
 * - User status updates (/status <online|away|busy>)
 * - Message history (stores last 100 messages)
 * - Notifications for join/leave
 * - Logging (server.log) for connections, disconnections, messages with timestamps
 *
 * Compile:
 *   g++ server.cpp -o server
 *
 * Run:
 *   ./server
 *
 * Notes:
 * - Uses a simple text file "users.txt" in the same folder to store username:password entries.
 * - For simplicity the server forwards file payloads and doesn't decode Base64; clients decode and save.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctime>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

const int PORT = 8080;
const int MAX_CLIENTS = 100;
const int BUFFER_SIZE = 4096;
const int HISTORY_LIMIT = 100;
const char *USERS_FILE = "users.txt";
const char *LOG_FILE = "server.log";

struct ClientInfo {
    int fd;
    std::string username;
    bool authenticated = false;
    std::string status = "online"; // online | away | busy
    sockaddr_in addr;
};

std::map<std::string, std::string> users; // username -> password
std::map<int, ClientInfo> clients;        // fd -> clientinfo
std::map<std::string, int> username_to_fd; // username -> fd
std::deque<std::string> history; // last messages

// ----------------- utilities -----------------
std::string now_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void append_log(const std::string &line) {
    // 1️⃣ Print to console
    std::cout << "[" << now_timestamp() << "] " << line << std::endl;

    // 2️⃣ Append to log file
    std::ofstream ofs(LOG_FILE, std::ios::app);
    ofs << "[" << now_timestamp() << "] " << line << std::endl;
    ofs.close();
}

void load_users() {
    users.clear();
    std::ifstream ifs(USERS_FILE);
    if (!ifs.is_open()) return;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        size_t p = line.find(':');
        if (p == std::string::npos) continue;
        std::string u = line.substr(0, p);
        std::string pw = line.substr(p+1);
        users[u] = pw;
    }
    ifs.close();
}

void save_user(const std::string &username, const std::string &password) {
    std::ofstream ofs(USERS_FILE, std::ios::app);
    ofs << username << ":" << password << std::endl;
    ofs.close();
    users[username] = password;
}

void push_history(const std::string &line) {
    history.push_back(line);
    if (history.size() > HISTORY_LIMIT) history.pop_front();
}

ssize_t send_all(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(fd, buf + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

ssize_t send_msg(int fd, const std::string &msg) {
    std::string with_newline = msg;
    if (with_newline.empty() || with_newline.back() != '\n') with_newline.push_back('\n');
    return send_all(fd, with_newline.c_str(), with_newline.size());
}

void broadcast(const std::string &msg, int except_fd = -1) {
    for (auto &p : clients) {
        int cfd = p.first;
        if (cfd == except_fd) continue;
        send_msg(cfd, msg);
    }
}

void send_private(const std::string &target, const std::string &msg) {
    if (username_to_fd.count(target)) {
        int fd = username_to_fd[target];
        send_msg(fd, msg);
    }
}

// ----------------- message parsing -----------------

// Helper: trim newline/carriage
inline void rstrip(std::string &s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
}

void handle_command(int fd, const std::string &line);

// Process a complete line from client
void process_line(int fd, const std::string &raw) {
    std::string line = raw;
    rstrip(line);
    if (line.empty()) return;

    // if client not authenticated, only allow AUTH or REGISTER
    if (!clients[fd].authenticated) {
        // Expect: AUTH username password  OR REGISTER username password
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd == "AUTH") {
            std::string username, password;
            iss >> username >> password;
            if (username.empty() || password.empty()) {
                send_msg(fd, "ERROR Missing username or password");
                return;
            }
            if (users.count(username) && users[username] == password) {
                clients[fd].authenticated = true;
                clients[fd].username = username;
                username_to_fd[username] = fd;
                std::string msg = "AUTH_OK Welcome " + username;
                send_msg(fd, msg);
                // notify others
                std::string note = "NOTIFY " + username + " joined";
                broadcast(note, fd);
                append_log("User " + username + " connected from fd " + std::to_string(fd));
                push_history(username + " joined");
                // send simple menu
                send_msg(fd, "MENU Commands: /msg <user> <text> , /file <user> <filename> , /status <online|away|busy> , /history <n> , /help , /exit");
            } else {
                send_msg(fd, "ERROR Invalid credentials");
            }
            return;
        } else if (cmd == "REGISTER") {
            std::string username, password;
            iss >> username >> password;
            if (username.empty() || password.empty()) {
                send_msg(fd, "ERROR Missing username or password for registration");
                return;
            }
            if (users.count(username)) {
                send_msg(fd, "ERROR Username already exists");
                return;
            }
            save_user(username, password);
            send_msg(fd, "REGISTER_OK User registered. Please AUTH to login.");
            append_log("User registered: " + username);
            return;
        } else {
            send_msg(fd, "ERROR Please authenticate first with: AUTH <username> <password>  or REGISTER <username> <password>");
            return;
        }
    }

    // Authenticated clients -> handle commands and messages
    if (!line.empty() && line[0] == '/') {
        // client used slash-style command locally, server expects commands like:
        // /msg <user> <text>  -> forwarded as PRIV <user> <text>
        // but we can simply parse common commands here:
        handle_command(fd, line);
        return;
    }

    // Or protocol-style commands: PRIV / FILE / STATUS / HISTORY / EXIT / HELP
    std::istringstream iss(line);
    std::string token;
    iss >> token;
    if (token == "PRIV") {
        // PRIV target rest...
        std::string target;
        iss >> target;
        std::string rest;
        std::getline(iss, rest);
        rstrip(rest);
        std::string out = "PRIVATE from " + clients[fd].username + ": " + rest;
        send_private(target, out);
        send_msg(fd, "SENT (to " + target + "): " + rest);
        append_log("PRIV " + clients[fd].username + " -> " + target + " : " + rest);
        push_history(clients[fd].username + " -> " + target + ": " + rest);
    } else if (token == "MSG") {
        std::string rest;
        std::getline(iss, rest);
        rstrip(rest);
        std::string out = "MSG " + clients[fd].username + ": " + rest;
        broadcast(out, fd);
        send_msg(fd, "SENT (broadcast): " + rest);
        append_log("MSG " + clients[fd].username + ": " + rest);
        push_history(clients[fd].username + ": " + rest);
    } else if (token == "STATUS") {
        std::string newstatus; iss >> newstatus;
        if (newstatus == "online" || newstatus == "away" || newstatus == "busy") {
            clients[fd].status = newstatus;
            std::string note = "STATUS " + clients[fd].username + " " + newstatus;
            broadcast(note, fd);
            send_msg(fd, "STATUS_OK " + newstatus);
            append_log("STATUS " + clients[fd].username + " -> " + newstatus);
        } else {
            send_msg(fd, "ERROR Invalid status. Use: /status <online|away|busy>");
        }
    } else if (token == "HISTORY") {
        int n = 10;
        iss >> n;
        if (n <= 0) n = 10;
        if (n > (int)history.size()) n = history.size();
        send_msg(fd, "HISTORY_BEGIN");
        int start = history.size() - n;
        for (int i = start; i < (int)history.size(); ++i) {
            send_msg(fd, std::to_string(i - start + 1) + ". " + history[i]);
        }
        send_msg(fd, "HISTORY_END");
    } else if (token == "FILE") {
        // FILE target filename size
        // After receiving this header line, server must read <size> bytes of payload from the socket and forward them.
        std::string target, filename;
        long long size;
        iss >> target >> filename >> size;
        if (target.empty() || filename.empty() || size <= 0) {
            send_msg(fd, "ERROR Invalid FILE header. Format: FILE <user> <filename> <size>");
            return;
        }
        // Read exact size bytes from fd
        std::string payload;
        payload.reserve(size);
        long long remaining = size;
        char buf[BUFFER_SIZE];
        while (remaining > 0) {
            ssize_t r = recv(fd, buf, std::min<long long>(BUFFER_SIZE, remaining), 0);
            if (r <= 0) {
                // connection error
                send_msg(fd, "ERROR during file transfer");
                return;
            }
            payload.append(buf, buf + r);
            remaining -= r;
        }
        // Forward to target if online
        if (username_to_fd.count(target)) {
            int tfd = username_to_fd[target];
            // send header to target: FILE <sender> <filename> <size>\n<payload>
            std::ostringstream hdr;
            hdr << "FILE " << clients[fd].username << " " << filename << " " << (long long)payload.size();
            send_msg(tfd, hdr.str());
            // send payload raw (no extra newline)
            send_all(tfd, payload.data(), payload.size());
            append_log("FILE forwarded from " + clients[fd].username + " to " + target + " : " + filename + " (" + std::to_string(payload.size()) + " bytes)");
            send_msg(fd, "FILE_SENT " + target);
            push_history("FILE " + clients[fd].username + " -> " + target + ": " + filename);
        } else {
            send_msg(fd, "ERROR User " + target + " not online");
        }
    } else if (token == "EXIT") {
        // handled by main loop closing socket
        send_msg(fd, "BYE");
    } else if (token == "HELP") {
        send_msg(fd, "HELP Commands: /msg <user> <text> , /file <user> <local_path> , /status <online|away|busy> , /history <n> , /help , /exit");
    } else {
        // treat as broadcast text
        std::string rest = line;
        std::string out = "MSG " + clients[fd].username + ": " + rest;
        broadcast(out, fd);
        send_msg(fd, "SENT (broadcast): " + rest);
        append_log("MSG " + clients[fd].username + ": " + rest);
        push_history(clients[fd].username + ": " + rest);
    }
}

// Handle slash commands sent by clients (if they typed /msg etc.)
void handle_command(int fd, const std::string &line) {
    // /msg <user> <text>
    std::istringstream iss(line);
    std::string cmd; iss >> cmd;
    if (cmd == "/msg") {
        std::string target; iss >> target;
        std::string rest; std::getline(iss, rest);
        rstrip(rest);
        std::string forward = "PRIVATE from " + clients[fd].username + ": " + rest;
        send_private(target, forward);
        send_msg(fd, "SENT (to " + target + "): " + rest);
        append_log("PRIV " + clients[fd].username + " -> " + target + " : " + rest);
        push_history(clients[fd].username + " -> " + target + ": " + rest);
    } else if (cmd == "/status") {
        std::string newstatus; iss >> newstatus;
        if (newstatus == "online" || newstatus == "away" || newstatus == "busy") {
            clients[fd].status = newstatus;
            std::string note = "STATUS " + clients[fd].username + " " + newstatus;
            broadcast(note, fd);
            send_msg(fd, "STATUS_OK " + newstatus);
            append_log("STATUS " + clients[fd].username + " -> " + newstatus);
        } else {
            send_msg(fd, "ERROR Invalid status. Use: /status <online|away|busy>");
        }
    } else if (cmd == "/history") {
        int n; iss >> n;
        if (!n) n = 10;
        if (n > (int)history.size()) n = history.size();
        send_msg(fd, "HISTORY_BEGIN");
        int start = history.size() - n;
        for (int i = start; i < (int)history.size(); ++i) {
            send_msg(fd, std::to_string(i - start + 1) + ". " + history[i]);
        }
        send_msg(fd, "HISTORY_END");
    } else if (cmd == "/help") {
        send_msg(fd, "HELP Commands: /msg <user> <text> , /file <user> <local_path> , /status <online|away|busy> , /history <n> , /help , /exit");
    } else if (cmd == "/exit") {
        send_msg(fd, "BYE");
        // main loop will detect and close
    } else if (cmd == "/file") {
        // instruct client to use FILE protocol: server expects client to send:
        // FILE <target> <filename> <size>\n<payload>
        std::string target, localpath;
        iss >> target >> localpath;
        if (target.empty() || localpath.empty()) {
            send_msg(fd, "ERROR Usage: /file <user> <local_path>");
            return;
        }
        // Let client handle reading file and sending FILE header & payload
        send_msg(fd, "READY_TO_SEND_FILE " + target);
    } else {
        send_msg(fd, "ERROR Unknown command. Use /help");
    }
}

// ----------------- main server loop -----------------

int main() {
    load_users();
    append_log("Server starting");

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 10) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(listen_fd, &master_set);
    int fdmax = listen_fd;

    std::cout << "Server listening on port " << PORT << "...\n";

    while (true) {
        read_fds = master_set;
        int activity = select(fdmax + 1, &read_fds, nullptr, nullptr, nullptr);
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }

        // New connection
        if (FD_ISSET(listen_fd, &read_fds)) {
            sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int newfd = accept(listen_fd, (sockaddr*)&client_addr, &addrlen);
            if (newfd < 0) {
                perror("accept");
            } else {
                FD_SET(newfd, &master_set);
                if (newfd > fdmax) fdmax = newfd;
                ClientInfo ci;
                ci.fd = newfd;
                ci.authenticated = false;
                ci.addr = client_addr;
                clients[newfd] = ci;

                // prompt for auth
                send_msg(newfd, "WELCOME Please AUTH <username> <password> or REGISTER <username> <password>");
                append_log("New connection fd " + std::to_string(newfd) + " from " + inet_ntoa(client_addr.sin_addr));
            }
        }

        // Check existing clients for data
        for (int fd = 0; fd <= fdmax; ++fd) {
            if (fd == listen_fd) continue;
            if (!FD_ISSET(fd, &read_fds)) continue;

            char buf[BUFFER_SIZE];
            ssize_t bytes = recv(fd, buf, sizeof(buf) - 1, 0);
            if (bytes <= 0) {
                // connection closed or error
                if (clients.count(fd) && clients[fd].authenticated) {
                    std::string uname = clients[fd].username;
                    append_log("User disconnected: " + uname);
                    std::string note = "NOTIFY " + uname + " left";
                    broadcast(note, fd);
                    push_history(uname + " left");
                    username_to_fd.erase(uname);
                } else {
                    append_log("Connection closed fd " + std::to_string(fd));
                }
                close(fd);
                FD_CLR(fd, &master_set);
                clients.erase(fd);
                continue;
            }

            // Received data: we assume messages are newline-terminated lines or special FILE payloads handled in process_line
            buf[bytes] = '\0';
            std::string incoming(buf, buf + bytes);

            // We might receive multiple lines at once; split on newline and process lines sequentially.
            std::istringstream ss(incoming);
            std::string line;
            while (std::getline(ss, line)) {
                // If a prior command instructed to read binary payload (FILE), that part is handled in process_line using raw recv()
                process_line(fd, line);
            }
        } // end clients loop
    } // end server loop

    close(listen_fd);
    append_log("Server shutting down");
    return 0;
}
