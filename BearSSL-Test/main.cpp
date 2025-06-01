#include <iostream>
#include <string>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <bearssl.h>
#include <libpsutil.h>

using namespace libpsutil::network;

int32_t userMain(void);

std::string resolve_hostname(const std::string& hostname)
{
    struct hostent* host_entry = gethostbyname(hostname.c_str());
    if (host_entry == nullptr)
    {
        printf("[DNS]: Failed to resolve hostname: %s\n", hostname.c_str());
        return "";
    }

    struct in_addr addr;
    addr.s_addr = *((unsigned long*)host_entry->h_addr_list[0]);
    std::string ip = inet_ntoa(addr);

    printf("[DNS]: Resolved %s to %s\n", hostname.c_str(), ip.c_str());
    return ip;
}

static bool http_get_request(const std::string& hostname, const std::string& path = "/")
{
    printf("[HTTP]: Starting request to %s%s\n", hostname.c_str(), path.c_str());

    // Resolve hostname to IP
    std::string server_ip = resolve_hostname(hostname);
    if (server_ip.empty())
    {
        return false;
    }

    // Create TCP socket
    socket web_socket(server_ip, 80, socket_type::SOCKET_TYPE_TCP);

    // Connect to server
    if (!web_socket.connect())
    {
        printf("[HTTP]: Connection failed\n");
        return false;
    }

    printf("[HTTP]: Connected successfully\n");

    // Build HTTP request
    std::string request =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + hostname + "\r\n"
        "Connection: close\r\n"
        "\r\n";

    printf("[HTTP]: Sending request...\n");

    // Send request
    if (!web_socket.send(request.c_str(), request.length()))
    {
        printf("[HTTP]: Failed to send request\n");
        web_socket.close();
        return false;
    }

    printf("[HTTP]: Request sent, waiting for response...\n");

    // Receive response
    char response[4096];
    memset(response, 0, sizeof(response));

    if (web_socket.receive(response, sizeof(response) - 1))
    {
        printf("[HTTP]: Response received:\n");
        printf("-----------------------------------\n");
        printf("%s\n", response);
        printf("-----------------------------------\n");
    }
    else
    {
        printf("[HTTP]: Failed to receive response\n");
        web_socket.close();
        return false;
    }

    web_socket.close();
    printf("[HTTP]: Connection closed\n");
    return true;
}


int32_t userMain(void)
{
	printf("Welcome to a simple http sample\n");
    http_get_request("httpbin.org", "/ip");
}