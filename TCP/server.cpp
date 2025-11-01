#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    char buffer[256];
    // Step 1: Create a TCP socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    // Step 2: Define server address (IP and port)
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080); // Port 8080
    server_address.sin_addr.s_addr = INADDR_ANY; // Listen on any network interface
    // Step 3: Bind the socket to the IP and port
    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    // Step 4: Listen for incoming connections
    listen(server_socket, 5);
    // Step 5: Accept a connection
    int client_socket = accept(server_socket, NULL, NULL);
    // Step 6: Send and receive messages
    recv(client_socket, buffer, sizeof(buffer), 0); // Receive message from client
    printf("Client: %s\n", buffer); // Print client message
    send(client_socket, "Hello from Server", 18, 0); // Send reply to client
    // Step 7: Close the sockets
    close(client_socket);
    close(server_socket);
return 0;
}