#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <array>

#define PORT 8080
#define BACKLOG 10
#define BUFFER_SIZE 1024

// Function to execute a shell command and return its output
std::string executeCommand(const std::string &cmd) {
    std::array<char, 128> buffer;
    std::string result;

    // Use '2>&1' to redirect stderr to stdout
    std::string full_command = cmd + " 2>&1"; 
    std::cout << "full_command - " << full_command << std::endl;

    FILE* pipe = popen(full_command.c_str(), "r");
    if (!pipe) {
        return "Failed to execute command\n";
    }

    std::cout << "command executed "  << std::endl;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    pclose(pipe);

    // Debug logging to check what is captured
    std::cout << "Executed command: " << full_command << std::endl;
    std::cout << "Command output: " << result << std::endl;

    return result;
}

void handleClient(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    std::string username, password;

    // Authentication flow
    ssize_t bytes_read;

    // Receive username
    std::cout << "Waiting to receive username from client..." << std::endl;
    bytes_read = recv(client_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_read <= 0) {
        std::cerr << "Failed to receive username" << std::endl;
        close(client_fd);
        return;
    }
    buffer[bytes_read] = '\0';
    username = buffer;
    std::cout << "Received username: " << username << std::endl;

    std::cout << "Waiting to receive password from client..." << std::endl;

    // Receive password
    bytes_read = recv(client_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_read <= 0) {
        std::cerr << "Failed to receive password" << std::endl;
        close(client_fd);
        return;
    }
    buffer[bytes_read] = '\0';
    password = buffer;
    std::cout << "Received password" << std::endl;

    if (username == "admin" && password == "password") {
        const char *auth_success = "Authentication successful\n";
        send(client_fd, auth_success, strlen(auth_success), 0);
        std::cout << auth_success << std::endl;
    } else {
        const char *auth_failed = "Authentication failed\n";
        send(client_fd, auth_failed, strlen(auth_failed), 0);
        std::cout << auth_failed << std::endl;
        close(client_fd);
        return;
    }

    // Command execution loop
    while (true) {
        std::string command;
        std::cout << "Waiting for commands from client..." << std::endl;

        bytes_read = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_read <= 0) {
            std::cerr << "Connection closed or error occurred" << std::endl;
            break; // Exit the loop if the client disconnects or an error occurs
        }
        buffer[bytes_read] = '\0';
        command = buffer;

        // Check for disconnect command
        if (command == "DISCONNECT\n") {
            std::cout << "Client has requested to disconnect." << std::endl;
            break; // Exit the loop and close the connection
        }  

        std::cout << "Received command - " << command << std::endl;
        // Execute the command and send the result back to the client
        std::cout << "Executing command: " << command;
        // Replace this with your command execution logic
        std::string result = executeCommand(command);
        send(client_fd, result.c_str(), result.size(), 0);std::cout << "Sent result back to client: " << result << std::endl;
        
    }

    std::cout << "Closing connection for client." << std::endl;
    close(client_fd);
}

void handleZombieProcesses(int sig) {
    while (waitpid(-1, nullptr, WNOHANG) > 0); // Clean up terminated child processes
}

int main() {
    signal(SIGCHLD, handleZombieProcesses); // Handle zombie processes

    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Socket created successfully." << std::endl;

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Socket bound to port " << PORT << "." << std::endl;

    // Start listening for incoming connections
    if (listen(server_fd, BACKLOG) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Server is listening on port " << PORT << std::endl;

    while (true) {
        // Accept a new client connection
        std::cout << "Waiting for a new client connection..." << std::endl;
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue; // Handle error and continue accepting
        }
        std::cout << "New client connected." << std::endl;

        // Create a new process to handle the client
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            close(server_fd); // Child doesn't need the listening socket
            handleClient(client_fd); // Handle the client
            std::cout << "Child process handling client is exiting." << std::endl;
            exit(0); // Exit child process after handling the client
        } else if (pid > 0) {
            // Parent process
            close(client_fd); // Parent doesn't need the client socket
            std::cout << "Parent process continues accepting new clients." << std::endl;
        } else {
            perror("Fork failed");
            close(client_fd);
        }
    }

    return 0;
}
