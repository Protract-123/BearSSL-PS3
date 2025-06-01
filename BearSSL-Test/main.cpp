#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdlib>
#include <bearssl.h>

constexpr int BUFFER_SIZE = 4096;

int string_to_port(const char* port_str) {
    int port = 0;
    while (*port_str >= '0' && *port_str <= '9') {
        port = port * 10 + (*port_str - '0');
        ++port_str;
    }
    return port;
}

// Low-level read callback for BearSSL I/O
static int sock_read(void* ctx, unsigned char* buf, size_t len) {
    int fd = *reinterpret_cast<int*>(ctx);
    while (true) {
        ssize_t r = ::read(fd, buf, len);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        return static_cast<int>(r);
    }
}

// Low-level write callback for BearSSL I/O
static int sock_write(void* ctx, const unsigned char* buf, size_t len) {
    int fd = *reinterpret_cast<int*>(ctx);
    while (true) {
        ssize_t w = ::write(fd, buf, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        return static_cast<int>(w);
    }
}

int main() {
    const char* host = "example.com";
    const char* port = "443";              // Use 443 for HTTPS
    bool use_https = std::string(port) == "443";

    // Resolve hostname
    hostent* server = gethostbyname(host);
    if (!server) {
        std::cerr << "Error: no such host: " << host << std::endl;
        return 1;
    }

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Build server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(string_to_port(port));
    std::memcpy(&server_addr.sin_addr, server->h_addr, server->h_length);

    // Connect
    if (connect(sockfd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // If HTTPS, perform TLS handshake
    br_sslio_context ioc;
    if (use_https) {
        // Initialize BearSSL client context
        br_ssl_client_context sc;
        br_x509_minimal_context xc;
        unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
        
        br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
        br_ssl_client_reset(&sc, host, 0);
        br_sslio_init(&ioc, &sc.eng, sock_read, &sockfd, sock_write, &sockfd);
    }

    // Build HTTP request
    std::string request = "GET / HTTP/1.1\r\n"
        "Host: " + std::string(host) + "\r\n"
        "Connection: close\r\n\r\n";

    if (use_https) {
        // Send over TLS
        br_sslio_write_all(&ioc, reinterpret_cast<const unsigned char*>(request.c_str()), request.size());
        br_sslio_flush(&ioc);
    }
    else {
        // Plain HTTP
        if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
            perror("send");
            close(sockfd);
            return 1;
        }
    }

    // Read response
    char buffer[BUFFER_SIZE];
    int rlen;
    if (use_https) {
        while ((rlen = br_sslio_read(&ioc, reinterpret_cast<unsigned char*>(buffer), sizeof(buffer) - 1)) > 0) {
            buffer[rlen] = '\0';
            std::cout << buffer;
        }
    }
    else {
        ssize_t bytes_received;
        while ((bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';
            std::cout << buffer;
        }
        if (bytes_received < 0) perror("recv");
    }

    // Close socket
    close(sockfd);
    return 0;
}


int32_t userMain(void)
{
	printf("Welcome to a simple http sample\n");
    main();
}