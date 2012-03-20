#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <event2/event.h>

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
 * Callback function that is called when packets are received.
 */

static void received_data(evutil_socket_t sock, short eventType, void *param)
{
	struct peer_info *p = param;

	printf("received_data()\n");
}

/*
 * Creates and binds a socket to accept packets.
 */

static evutil_socket_t create_socket(char *addr, int *port)
{
	/* create server socket */
	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed\n");
		return -1;
	}
	evutil_make_socket_nonblocking(sock);

	/* bind the socket */
	struct sockaddr_storage ss;
	int len = sizeof(struct sockaddr_storage);
	evutil_parse_sockaddr_port(addr, (struct sockaddr *)&ss, &len);
	if (bind(sock, (struct sockaddr *)&ss, len)) {
		printf("bind() failed: %s\n", strerror(errno));
		return -1;
	}

	/* provide the port it is running on */
	getsockname(sock, (struct sockaddr *)&ss, &len);
	if (ss.ss_family == AF_INET) {
		*port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
	}
	else if (ss.ss_family == AF_INET6) {
		*port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
	}
	else {
		printf("Address type not recognized\n");
		return -1;
	}

	return sock;
}

/*
 * Gets the crypto keys and initializes the UDP server.
 */

static int start_node(struct event_base *base, int node_num)
{
	/* create or load the keys */
	void *priv = NULL, *pub = NULL;
	if (node_num > 1 || !file_exists(PRIV_FILE)) {
		if (!create_private_key(&priv) ||
			!create_public_key(&pub, priv))
		{
			return 0;
		}
		if (node_num == 1) {
			if (!write_private_key(priv, PRIV_FILE) ||
				!write_public_key(pub, PUB_FILE))
			{
				return 0;
			}
		}
	}
	else if (!read_private_key(&priv, PRIV_FILE) ||
		!read_public_key(&pub, PUB_FILE))
	{
		return 0;
	}

	/* read the config file if necessary */
	char addr[20];
	if (node_num == 1 && file_exists(CONFIG_FILE)) {
		if (!read_config(CONFIG_FILE, "udpsrv", addr)) {
			printf("Failed to read config\n");
			return 0;
		}
	}
	else {
		strcpy(addr, "127.0.0.1");
	}

	/* create the server socket */
	int port;
	evutil_socket_t sock;
	if ((sock = create_socket(addr, &port)) < 0) {
		return 0;
	}
	printf("Using UDP port %hu\n", port);

	/* create the DTLS context */
	void *ctx = NULL;
	if (!dtls_global_init(&ctx, priv, pub)) {
		return 0;
	}

	/* create the struct to pass to the callback function */
	struct peer_info *p = malloc(sizeof(struct peer_info));
	p->base = base;
	p->ctx = ctx;
	p->ssl = NULL;

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
			fprintf(file, "udpsrv\t\t\t%s:%hu\n\n", addr, port) < 0 ||
			fprintf(file, "# Port used locally by SOCKS-enabled apps\n") < 0 ||
			fprintf(file, "socsrv\t\t\t%s:9050\n\n", addr) < 0 ||
			fprintf(file, "# If YES, you'll find peers automatically\n") < 0 ||
			fprintf(file, "autoip\t\t\tYES\n\n") < 0)
		{
			printf("Failed to write config\n");
			fclose(file);
			return 0;
		}
		fclose(file);
	}

	if (node_num > 1) {
		int port2;
		evutil_socket_t sock2;
		if ((sock2 = create_socket("127.0.0.1", &port2)) < 0) {
			return 0;
		}

		struct sockaddr_storage ss;
		int len = sizeof(struct sockaddr_storage);
		evutil_parse_sockaddr_port
			("127.0.0.1:63306", (struct sockaddr *)&ss, &len);
		if (connect(sock2, (struct sockaddr *)&ss, len) < 0) {
			printf("connect() failed\n");
			return 0;
		}

		void *ssl2;
		if (!dtls_client_init(&ssl2, sock2, ctx, &ss)) {
			printf("%s\n", strerror(errno));
			return 0;
		}
	}

	return 1;
}

/*
 * Initializes and begins listening for events.
 */

int main(int argc, char** argv)
{
	signal(SIGPIPE, SIG_IGN);

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
	//for (; count > 0; count--) {
	int i = 1;
	for (; i <= count; i++) {
		if (!start_node(base, i)) {
			return 1;
		}
	}
	event_base_dispatch(base);
}
