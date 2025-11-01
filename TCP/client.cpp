#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    char buffer[256];
    // Step 1: Create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // Step 2: Define server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080); // Server port
    server_address.sin_addr.s_addr = INADDR_ANY; // Server IP
    // Step 3: Connect to the server
    connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
    // Step 4: Send and receive messages
    send(sock, "Hello from Client", 18, 0); // Send message to server
    recv(sock, buffer, sizeof(buffer), 0); // Receive message from server
    printf("Server: %s\n", buffer); // Print server message
    // Step 5: Close the socket
    close(sock);
return 0;
}