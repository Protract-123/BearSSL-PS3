#include <stdio.h>
#include <netex/net.h>
#include <sys/process.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cell/sysmodule.h>
#include <inttypes.h>
#include <bearssl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#include "ta.hpp"

SYS_PROCESS_PARAM(1001, 0x100000)

static const char* TARGET_HOST = "www.howsmyssl.com";
static const char* TARGET_PORT = "443";
static const char* TARGET_PATH = "/a/check";

static int
host_connect(const char* host, const char* port)
{
	struct hostent* he;
	struct sockaddr_in addr;
	int fd;
	int port_num;

	/* Convert port string to integer */
	port_num = atoi(port);
	if (port_num <= 0 || port_num > 65535) {
		printf("ERROR: Invalid port number\n");
		return -1;
	}

	/* Get host information */
	he = gethostbyname(host);
	if (he == NULL) {
		printf("ERROR: gethostbyname() failed\n");
		return -1;
	}

	/* Check if it's IPv4 */
	if (he->h_addrtype != AF_INET) {
		printf("ERROR: Host does not have IPv4 address\n");
		return -1;
	}

	/* Create socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("ERROR: socket() failed\n");
		return -1;
	}

	#ifdef O_NONBLOCK
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0) {
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
		printf("Socket set to blocking mode\n");
	}
	#endif

	/* Setup address structure */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((unsigned short)port_num);
	memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

	printf("connecting to: %s\n", inet_ntoa(addr.sin_addr));

	/* Connect to server */
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		printf("ERROR: connect() failed\n");
		close(fd);
		return -1;
	}

	printf("connected to: %s\n", inet_ntoa(addr.sin_addr));
	return fd;
}

static int
sock_read(void* ctx, unsigned char* buf, size_t len)
{
	int fd = *(int*)ctx;
	ssize_t rlen;
	for (;;) {
		rlen = recv(fd, buf, len, 0);
		if (rlen > 0) {
			return (int)rlen;
		}
		if (rlen == 0) {
			printf("sock_read: connection closed by peer (EOF)\n");
			return -1;
		}
		/* rlen < 0 - error occurred */
		if (errno == EINTR) {
			printf("sock_read: interrupted, retrying...\n");
			continue;
		}
		if (errno == EAGAIN) {
			printf("sock_read: would block (non-blocking socket?)\n");
			return -1;
		}
		printf("sock_read: error %d (%s)\n", errno, strerror(errno));
		return -1;
	}
}

static int
sock_write(void* ctx, const unsigned char* buf, size_t len)
{
	int fd = *(int*)ctx;
	ssize_t wlen;
	for (;;) {
		wlen = send(fd, buf, len, 0);
		if (wlen > 0) {
			return (int)wlen;
		}
		if (wlen == 0) {
			printf("sock_write: send returned 0 (unusual)\n");
			return -1;
		}
		/* wlen < 0 - error occurred */
		if (errno == EINTR) {
			printf("sock_write: interrupted, retrying...\n");
			continue;
		}
		if (errno == EAGAIN) {
			printf("sock_write: would block (non-blocking socket?)\n");
			return -1;
		}
		if (errno == EPIPE) {
			printf("sock_write: broken pipe (connection closed)\n");
			return -1;
		}
		printf("sock_write: error %d (%s)\n", errno, strerror(errno));
		return -1;
	}
}

static int check_socket_valid(int fd) {
	int error = 0;
	socklen_t len = sizeof(error);
	int result;

	/* Try to get socket error status */
	result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (result == 0) {
		if (error != 0) {
			printf("Socket has error condition!\n");
			return 0;
		}
	}
	else {
		printf("getsockopt failed with errno: %d\n", errno);
		return 0;
	}

	/* Try to get socket type to verify it's still valid */
	int sock_type;
	len = sizeof(sock_type);
	result = getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &len);
	if (result == 0) {
		if (sock_type != SOCK_STREAM) {
			printf("Socket type: %d (should be %d for SOCK_STREAM)\n", sock_type, SOCK_STREAM);
		}
	}
	else {
		printf("Could not get socket type - socket may be invalid\n");
		return 0;
	}

	return 1;
}

static void inject_entropy(br_ssl_engine_context* eng) {
	unsigned char entropy_pool[32]; /* 256 bits of entropy */
	int i;
	time_t current_time;
	clock_t current_clock;
	uintptr_t stack_addr;
	static unsigned int call_counter = 0;

	/* Gather entropy from multiple sources */
	current_time = time(NULL);
	current_clock = clock();
	stack_addr = (uintptr_t)&entropy_pool;
	call_counter++;

	/* Fill entropy pool with mixed sources */
	for (i = 0; i < 32; i++) {
		unsigned char byte_val = 0;

		/* Mix time-based entropy */
		byte_val ^= (unsigned char)(current_time >> (i % 8));
		byte_val ^= (unsigned char)(current_clock >> (i % 8));

		/* Mix address-based entropy (ASLR if available) */
		byte_val ^= (unsigned char)(stack_addr >> (i % 8));

		/* Mix counter and position */
		byte_val ^= (unsigned char)(call_counter * (i + 1));

		/* Add some mathematical variation */
		byte_val ^= (unsigned char)((i * 17 + 31) ^ (i << 3));

		/* Simple avalanche effect */
		if (i > 0) {
			byte_val ^= entropy_pool[i - 1];
		}

		entropy_pool[i] = byte_val;
	}

	/* Additional mixing pass to improve distribution */
	for (i = 1; i < 32; i++) {
		entropy_pool[i] ^= entropy_pool[i - 1];
		entropy_pool[i] = (entropy_pool[i] << 1) | (entropy_pool[i] >> 7); /* rotate left */
	}

	/* Inject the entropy into BearSSL engine */
	br_ssl_engine_inject_entropy(eng, entropy_pool, sizeof(entropy_pool));

	printf("Injected %zu bytes of entropy into SSL engine\n", sizeof(entropy_pool));

	/* Clear entropy pool from stack (basic security hygiene) */
	for (i = 0; i < 32; i++) {
		entropy_pool[i] = 0;
	}
}

static void set_ssl_time(br_x509_minimal_context* xc) {
	time_t current_time;
	uint32_t days, seconds;

	// Get current time
	current_time = time(NULL);

	if (current_time == (time_t)-1) {
		printf("Warning: Could not get system time, using fallback\n");
		// Use a reasonable fallback time incase time can't be fetched
		// Unix Epoch (Jan 1, 1970) = 719528 days since 0 AD
		// 1st June 2025 is about 20244 days away from that
		days = 719528 + 20240;
		seconds = 0;
	}
	else {
		// Convert Unix timestamp to BearSSL format
		// Unix Epoch (Jan 1, 1970, 00:00 UTC) = 719528 days since 0 AD
		days = 719528 + (uint32_t)(current_time / 86400);  // Add days since Unix epoch
		seconds = (uint32_t)(current_time % 86400);        // Seconds within the day
	}

	// Set the validation time in the X.509 context
	br_x509_minimal_set_time(xc, days, seconds);
}

int main(void)
{
	/* Init PS3 Network */
	int ret;

	ret = cellSysmoduleLoadModule(CELL_SYSMODULE_HTTP);
	if (ret < 0) {
		printf("cellSysmoduleLoadModule failed (0x%x)\n", ret);
		return 0;
	}

	ret = sys_net_initialize_network();
	if (ret < 0) {
		printf("sys_net_initialize_network() failed (0x%x)\n", ret);
		return 0;
	}

	/* Init BearSSL Variables */
	int fd;
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_sslio_context ioc;

	/* Connect to target */
	fd = host_connect(TARGET_HOST, TARGET_PORT);
	if (fd < 0) {
		return EXIT_FAILURE;
	}

	/* Check if socket is valid */
	if (!check_socket_valid(fd)) {
		printf("Socket invalid after connect!\n");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Initialize BearSSL Client  */
	br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
	printf("SSL client context initialized\n");
	printf("Buffer size: %zu\n", sizeof(iobuf));
	printf("Trust anchors count: %zu\n", TAs_NUM);

	/* Add entropy and time */
	inject_entropy(&sc.eng);
	set_ssl_time(&xc);

	/* Check if socket is valid */
	if (!check_socket_valid(fd)) {
		printf("Socket invalid after SSL init!\n");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Give the engine a buffer */
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);

	/* Establish New SSL Connection */
	br_ssl_client_reset(&sc, TARGET_HOST, 0);

	if (!check_socket_valid(fd)) {
		printf("Socket invalid after SSL reset!\n");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Init SSL IO */
	br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);
	if (!check_socket_valid(fd)) {
		printf("Socket invalid after sslio_init!\n");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Queue GET Request */
	printf("About to send HTTP request...\n");
	int write_result;

	if (!check_socket_valid(fd)) {
		printf("Socket became invalid before write attempt!\n");
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Sending GET request...\n");
	write_result = br_sslio_write_all(&ioc, "GET ", 4);
	if (write_result < 0) {
		printf("Failed to write 'GET ', SSL state: %u, error: %d\n",
			br_ssl_engine_current_state(&sc.eng), br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Sending path...\n");
	write_result = br_sslio_write_all(&ioc, TARGET_PATH, strlen(TARGET_PATH));
	if (write_result < 0) {
		printf("Failed to write path, SSL state: %u, error: %d\n",
			br_ssl_engine_current_state(&sc.eng), br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Sending HTTP version and headers...\n");
	write_result = br_sslio_write_all(&ioc, " HTTP/1.0\r\nHost: ", 17);
	if (write_result < 0) {
		printf("Failed to write HTTP headers, SSL state: %u, error: %d\n",
			br_ssl_engine_current_state(&sc.eng), br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Sending hostname...\n");
	write_result = br_sslio_write_all(&ioc, TARGET_HOST, strlen(TARGET_HOST));
	if (write_result < 0) {
		printf("Failed to write hostname, SSL state: %u, error: %d\n",
			br_ssl_engine_current_state(&sc.eng), br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Sending final headers...\n");
	write_result = br_sslio_write_all(&ioc, "\r\n\r\n", 4);
	if (write_result < 0) {
		printf("Failed to write final headers, SSL state: %u, error: %d\n",
			br_ssl_engine_current_state(&sc.eng), br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	printf("All HTTP request data written, attempting flush...\n\n");

	/* Send GET Request*/
	if (br_sslio_flush(&ioc) < 0) {
		printf("ERROR: Failed to flush SSL output\n");
		printf("SSL state: %u, SSL error: %d\n",
			br_ssl_engine_current_state(&sc.eng),
			br_ssl_engine_last_error(&sc.eng));
		close(fd);
		return EXIT_FAILURE;
	}

	/* Recieve Response */
	for (;;) {
		int rlen;
		unsigned char tmp[512];

		rlen = br_sslio_read(&ioc, tmp, sizeof(tmp));
		if (rlen < 0) {
			break;
		}
		fwrite(tmp, 1, rlen, stdout);
	}
	printf("\n\n");
	close(fd);

	if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
		int err;

		err = br_ssl_engine_last_error(&sc.eng);
		if (err == 0) {
			printf("Connection closed.\n");
			return EXIT_SUCCESS;
		}
		else {
			printf("SSL error %d\n", err);
			return EXIT_FAILURE;
		}
	}
	else {
		printf("socket closed without proper SSL termination\n");
		return EXIT_FAILURE;
	}

	/* Unload PS3 Network */
	sys_net_finalize_network();

	ret = cellSysmoduleUnloadModule(CELL_SYSMODULE_HTTP);
	if (ret < 0) {
		printf("cellSysmoduleUnloadModule failed (0x%x)\n", ret);
		return 0;
	}

	return 0;
}
