#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <event2/event.h>
#include <netinet/in.h>

#include "crypto.h"
#include "util.h"

#define PRIV_FILE "private.pem"
#define PUB_FILE "public.pem"
#define CONFIG_FILE  "seejay.conf"

struct peer_info {
	struct event_base *base; /* Libevent structure */
	void *ctx; /* points to the global SSL_CTX structure */
	void *ssl; /* points to a specific SSL structure */
};

/*
 * Creates and binds a socket, providing the port number via pointer.
 */

static evutil_socket_t create_socket(char *addr_str, int *port)
{
	/* create the server socket */
	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed\n");
		return -1;
	}
	evutil_make_socket_nonblocking(sock);

	/* bind the server socket */
	struct sockaddr_storage addr;
	int len = sizeof(addr);
	evutil_parse_sockaddr_port(addr_str, (struct sockaddr*)&addr, &len);
	if (bind(sock, (struct sockaddr*)&addr, len)) {
		printf("bind() failed: %s\n", strerror(errno));
		return -1;
	}

	/* provide the port it is running on */
	getsockname(sock, (struct sockaddr*)&addr, &len);
	*port = ntohs(((struct sockaddr_in*)&addr)->sin_port);

	return sock;
}

/*
 * Callback function that is called when a packet is received.
 */

static void received_data(evutil_socket_t sock, short eventType, void* param)
{
	struct peer_info *p = (struct peer_info *)param;

	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} client_addr;

	/* this is the server socket */
	if (p->ssl == NULL) {
		void *ssl = NULL;
		if (!dtls_server_listen(sock, p->ctx, &client_addr, &ssl)) {
			printf("dtls_server_listen() failed\n");
		}
		else {
			printf("dtls_server_listen() succeeded\n");
		}
	}
	/* this is a specific peer */
	else {
		
	}
}

/*
 * Gets the crypto keys and initializes the UDP socket.
 */

static evutil_socket_t start_node(struct event_base *base, int node_num)
{
	/* create or load the keys */
	void *priv = NULL, *pub = NULL;
	if (node_num > 1 || !file_exists(PRIV_FILE)) {
		if (!create_private_key(&priv) ||
			!create_public_key(priv, &pub))
		{
			return -1;
		}
		if (node_num == 1) {
			if (!write_private_key(priv, PRIV_FILE) ||
				!write_public_key(pub, PUB_FILE))
			{
				return -1;
			}
		}
	}
	else if (!read_private_key(&priv, PRIV_FILE) ||
		!read_public_key(&pub, PUB_FILE))
	{
		return -1;
	}

	/* read the config file if necessary */
	char addr_str[20];
	if (node_num == 1 && file_exists(CONFIG_FILE)) {
		if (!read_config(CONFIG_FILE, "udpsrv", addr_str)) {
			printf("Failed to read config\n");
			return -1;
		}
	}
	else {
		strcpy(addr_str, "127.0.0.1");
	}

	/* create the socket */
	int port;
	evutil_socket_t sock;
	if ((sock = create_socket(addr_str, &port)) < 0) {
		return -1;
	}
	printf("Using UDP port %hu\n", port);

	/* initiate the DTLS server */
	struct peer_info *p = malloc(sizeof(struct peer_info));
	p->base = base;
	p->ctx = p->ssl = NULL;
	if (!dtls_server_init(&p->ctx, priv, pub)) {
		return -1;
	}

	/* add it to the event loop */
	struct event *evt =
		event_new(base, sock, EV_READ | EV_PERSIST, received_data, p);
	if (evt == NULL) {
		printf("event_new() failed\n");
		return -1;
	}
	event_add(evt, NULL);

	/* write the config file if necessary */
	if (node_num == 1 && !file_exists(CONFIG_FILE)) {
		FILE *file = fopen(CONFIG_FILE, "w");
		if (fprintf(file, "# Port to accept peers on (forward it!)\n") < 0 ||
			fprintf(file, "udpsrv\t\t\t%s:%hu\n\n", addr_str, port) < 0 ||
			fprintf(file, "# Port used locally by SOCKS-enabled apps\n") < 0 ||
			fprintf(file, "socsrv\t\t\t%s:9050\n\n", addr_str) < 0 ||
			fprintf(file, "# If YES, you'll find peers automatically\n") < 0 ||
			fprintf(file, "autoip\t\t\tYES\n\n") < 0)
		{
			printf("Failed to write config\n");
			fclose(file);
			return -1;
		}
		fclose(file);
	}

	return sock;
}

/*
 * Initializes and begins listening for events.
 */

int main(int argc, char** argv)
{
	/* determine if we are running in test mode */
	int count = 1;
	while (argc > 0) {
		argc--;
		if (!strcmp(argv[argc], "--test")) {
			count = 2;
		}
	}

	/* start the node(s) and enter the event loop */
	struct event_base *base = event_base_new();
	evutil_socket_t sock;
	for (; count > 0; count--) {
		if ((sock = start_node(base, count)) < 0) {
			return 1;
		}
	}
	event_base_dispatch(base);
}
