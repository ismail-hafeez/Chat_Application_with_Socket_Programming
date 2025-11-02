/* client.cpp
 *
 * TCP Chat Client (C++)
 *
 * Client provides:
 * - Connect to server on localhost:8080
 * - Authentication (AUTH or REGISTER)
 * - Interactive input loop for commands:
 *     /msg <user> <text>
 *     /file <user> <local_path>
 *     /status <online|away|busy>
 *     /history <n>
 *     /help
 *     /exit
 * - File transfer: client reads local file, Base64 encodes it, then sends a FILE header and payload to server:
 *     FILE <target> <filename> <size>\n<payload>
 *   Client also handles incoming FILE headers from server and saves decoded files to disk.
 *
 * Compile:
 *   g++ client.cpp -o client -pthread
 *
 * Run:
 *   ./client
 *
 * Notes:
 *  - This client uses a receiver thread to print server messages and handle incoming file payloads.
 *  - Files are base64 encoded when sent; incoming file payloads are base64 decoded and saved as received_from_<sender>_<filename>
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

// ---------------- Base64 (encode/decode) ----------------
// Simple base64 implementations (works for this assignment)
static const std::string b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val=0, valb=-6;
    for (unsigned char c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val>>valb)&0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string &in) {
    std::vector<int> T(256,-1);
    for (int i=0;i<64;i++) T[(unsigned char)b64_chars[i]] = i;
    std::string out;
    std::vector<int> buf(4,0);
    int val=0, valb=-8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val>>valb)&0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ---------------- networking helpers ----------------
ssize_t send_all(int sock, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sock, buf + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

ssize_t send_msg(int sock, const std::string &msg) {
    std::string out = msg;
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    return send_all(sock, out.c_str(), out.size());
}

// Read exactly n bytes (used for file payloads)
bool recv_nbytes(int sock, std::string &out, long long n) {
    out.clear();
    out.reserve(n);
    char buf[BUFFER_SIZE];
    long long remaining = n;
    while (remaining > 0) {
        ssize_t r = recv(sock, buf, std::min<long long>(BUFFER_SIZE, remaining), 0);
        if (r <= 0) return false;
        out.append(buf, buf + r);
        remaining -= r;
    }
    return true;
}

// ---------------- client receiver thread ----------------
std::atomic<bool> running(true);
int sockfd_global = -1;
std::mutex print_mutex;

void save_file_from_sender(const std::string &sender, const std::string &filename, const std::string &payload_b64) {
    std::string decoded = base64_decode(payload_b64);
    std::string outname = "received_from_" + sender + "_" + filename;
    std::ofstream ofs(outname, std::ios::binary);
    ofs.write(decoded.data(), decoded.size());
    ofs.close();
    std::lock_guard<std::mutex> lg(print_mutex);
    std::cout << "[FILE] Saved file as: " << outname << " (" << decoded.size() << " bytes)\n";
}

void receiver_thread(int sock) {
    char buf[BUFFER_SIZE];
    std::string leftover;
    while (running) {
        ssize_t bytes = recv(sock, buf, sizeof(buf)-1, 0);
        if (bytes <= 0) {
            std::lock_guard<std::mutex> lg(print_mutex);
            std::cout << "Disconnected from server.\n";
            running = false;
            break;
        }
        // append to leftover and process lines
        leftover.append(buf, buf + bytes);

        // Process possible FILE headers that include payload immediately after header
        while (true) {
            // If leftover contains a newline, we can parse a header line
            size_t nlpos = leftover.find('\n');
            if (nlpos == std::string::npos) break;
            std::string line = leftover.substr(0, nlpos);
            leftover.erase(0, nlpos + 1);
            // Trim CR if present
            if (!line.empty() && line.back() == '\r') line.pop_back();

            // Check if header indicates a file incoming:
            // Header format: FILE <sender> <filename> <size>
            if (line.rfind("FILE ", 0) == 0) {
                std::istringstream iss(line);
                std::string tag, sender, filename;
                long long size;
                iss >> tag >> sender >> filename >> size;
                if (size <= 0) {
                    std::lock_guard<std::mutex> lg(print_mutex);
                    std::cout << "[ERROR] Invalid incoming file size\n";
                    continue;
                }
                // Ensure leftover contains 'size' bytes; if not, read more from socket
                std::string payload;
                if ((long long)leftover.size() >= size) {
                    payload = leftover.substr(0, size);
                    leftover.erase(0, size);
                } else {
                    // Need to read remaining bytes
                    payload = leftover;
                    long long remaining = size - payload.size();
                    leftover.clear();
                    std::string rest;
                    if (!recv_nbytes(sock, rest, remaining)) {
                        std::lock_guard<std::mutex> lg(print_mutex);
                        std::cout << "[ERROR] Connection lost during file receive\n";
                        running = false;
                        return;
                    }
                    payload += rest;
                }
                // payload contains Base64 string
                save_file_from_sender(sender, filename, payload);
            } else {
                // Regular textual line from server; print it
                std::lock_guard<std::mutex> lg(print_mutex);
                std::cout << line << std::endl;
            }
        }
    }
}

// ---------------- main client logic ----------------
int main() {
    std::string server_ip = "127.0.0.1";

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    inet_pton(AF_INET, server_ip.c_str(), &servaddr.sin_addr);

    if (connect(sock, (sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    sockfd_global = sock;

    // start receiver thread
    std::thread recv_t(receiver_thread, sock);

    // Authentication flow
    std::cout << "Connected to server. You must authenticate.\n";
    while (true) {
        std::cout << "Choose: (1) AUTH  (2) REGISTER : ";
        std::string choice; std::getline(std::cin, choice);
        if (choice == "1" || choice == "AUTH") {
            std::string username, password;
            std::cout << "Username: "; std::getline(std::cin, username);
            std::cout << "Password: "; std::getline(std::cin, password);
            std::string auth = "AUTH " + username + " " + password;
            send_msg(sock, auth);
            // Wait for a short response from server (the receiver thread prints it). We assume server accepts or rejects.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            break;
        } else if (choice == "2" || choice == "REGISTER") {
            std::string username, password;
            std::cout << "Choose username: "; std::getline(std::cin, username);
            std::cout << "Choose password: "; std::getline(std::cin, password);
            std::string reg = "REGISTER " + username + " " + password;
            send_msg(sock, reg);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            // After registering, prompt to auth
            std::cout << "Now AUTH using the credentials.\n";
        } else {
            std::cout << "Unknown choice, try again.\n";
        }
    }

    // Main interactive loop
    while (running) {
        std::string line;
        {
            std::lock_guard<std::mutex> lg(print_mutex);
            std::cout << "> ";
        }
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Commands starting with '/'
        if (line.rfind("/msg ", 0) == 0) {
            // /msg <user> <text>
            std::istringstream iss(line);
            std::string cmd, target;
            iss >> cmd >> target;
            std::string rest; std::getline(iss, rest);
            std::string proto = "PRIV " + target + " " + rest;
            send_msg(sock, proto);
        } else if (line.rfind("/file ", 0) == 0) {
            // /file <user> <local_path>
            std::istringstream iss(line);
            std::string cmd, target, path;
            iss >> cmd >> target >> path;
            if (target.empty() || path.empty()) {
                std::cout << "Usage: /file <user> <local_path>\n";
                continue;
            }
            // read file
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs.is_open()) {
                std::cout << "Cannot open " << path << "\n";
                continue;
            }
            std::ostringstream ss;
            ss << ifs.rdbuf();
            std::string raw = ss.str();
            ifs.close();
            std::string payload_b64 = base64_encode(raw);
            // Use filename as last component of path
            size_t p = path.find_last_of("/\\");
            std::string filename = (p == std::string::npos) ? path : path.substr(p+1);
            // Send header: FILE <target> <filename> <size>\n<payload>
            std::ostringstream hdr;
            hdr << "FILE " << target << " " << filename << " " << payload_b64.size();
            send_msg(sock, hdr.str());
            // send payload raw (no newline)
            if (send_all(sock, payload_b64.data(), payload_b64.size()) <= 0) {
                std::cout << "Error sending file payload\n";
            } else {
                std::cout << "File sent to server for delivery to " << target << "\n";
            }
        } else if (line.rfind("/status ", 0) == 0) {
            // /status <online|away|busy>
            std::istringstream iss(line);
            std::string cmd, st; iss >> cmd >> st;
            std::string proto = "STATUS " + st;
            send_msg(sock, proto);
        } else if (line.rfind("/history", 0) == 0) {
            // /history <n>
            std::istringstream iss(line);
            std::string cmd; int n;
            iss >> cmd >> n;
            if (n <= 0) n = 10;
            std::ostringstream proto; proto << "HISTORY " << n;
            send_msg(sock, proto.str());
        } else if (line == "/help") {
            send_msg(sock, "HELP");
        } else if (line == "/exit") {
            send_msg(sock, "EXIT");
            running = false;
            break;
        } else {
            // normal broadcast text - send as MSG
            std::string proto = "MSG " + line;
            send_msg(sock, proto);
        }
    }

    // cleanup
    running = false;
    shutdown(sock, SHUT_RDWR);
    close(sock);
    if (recv_t.joinable()) recv_t.join();
    std::cout << "Client terminated.\n";
    return 0;
}
