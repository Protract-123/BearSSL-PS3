#include <stdio.h>
#include <netex/net.h>
#include <sys/process.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libpsutil.h>
#include <cell/sysmodule.h>
#include <inttypes.h>

using namespace libpsutil::network;

SYS_PROCESS_PARAM(1001, 0x10000)

int main(void)
{
	int ret;

	ret = cellSysmoduleLoadModule(CELL_SYSMODULE_HTTP);
	if (ret < 0) {
		printf("cellSysmoduleLoadModule failed (0x%x)\n", ret);
		return 0;
	}

	/*E start network */
	ret = sys_net_initialize_network();
	if (ret < 0) {
		printf("sys_net_initialize_network() failed (0x%x)\n", ret);
		return 0;
	}

	// User Start
	const std::string& hostname = "httpbin.org";
	hostent* host = gethostbyname(hostname.data());

	char* ip_buffer = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);

	printf("IP: %s\n", ip_buffer);



	socket http_socket(ip_buffer, 80, SOCKET_TYPE_TCP);
	
	if (!http_socket.connect()) {
		printf("Socket failed to connect");
		http_socket.close();
		return 1;
	}

	std::string http_request =
		"GET /get HTTP/1.1\r\n"
		"Host: httpbin.org\r\n"
		"User-Agent: SimpleClient/1.0\r\n"
		"Connection: close\r\n"
		"\r\n";

	if (!http_socket.send(http_request.c_str(), http_request.length())) {
		printf("Failed to send HTTP request");
		http_socket.close();
		return -1;
	}

	// Receive the response
	char response_buffer[4096];
	memset(response_buffer, 0, sizeof(response_buffer));

	if (!http_socket.receive(response_buffer, sizeof(response_buffer) - 1))
	{
		printf("Failed to receive HTTP response");
		http_socket.close();
		return -1;
	}

	printf(response_buffer);

	http_socket.close();

	sys_net_finalize_network();

	/*E unload relocatable modules */
	ret = cellSysmoduleUnloadModule(CELL_SYSMODULE_HTTP);
	if (ret < 0) {
		printf("cellSysmoduleUnloadModule failed (0x%x)\n", ret);
		return 0;
	}
	return 0;
}