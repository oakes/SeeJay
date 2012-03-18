#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "crypto.h"
#include "util.h"

#define PRIV_FILE "private.pem"
#define PUB_FILE "public.pem"
#define CONFIG_FILE  "seejay.conf"

struct peer_info {
	struct event_base *base; /* Libevent structure */
	void *ctx; /* points to the global SSL_CTX structure */
	void *ssl; /* points to a specific SSL structure */
	void *bev; /* points to a bufferevent structure */
};

/*
 * Callback function that is called when the server receives a packet.
 */

static void server_recv(evutil_socket_t sock, short eventType, void* param)
{
	struct peer_info *p = (struct peer_info *)param;

	printf("server_recv()\n");
}

/*
 * Callback function that is called when the client receives a packet.
 */

static void client_recv(struct bufferevent *bev, void *param)
{
	struct peer_info *p = (struct peer_info *)param;

	printf("client_recv()\n");
}

static void client_event(struct bufferevent *bev, short what, void *param)
{
	struct peer_info *p = (struct peer_info *)param;

	if (what == BEV_EVENT_ERROR) {
		printf("Unrecoverable error encountered\n");
	}
}

/*
 * Creates and binds a socket to accept packets.
 */

static int create_server
	(struct event_base *base, void *ctx, char *addr, int *port)
{
	/* create server socket */
	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed\n");
		return 0;
	}
	evutil_make_socket_nonblocking(sock);

	/* bind the socket */
	struct sockaddr_storage ss;
	int len = sizeof(struct sockaddr_storage);
	evutil_parse_sockaddr_port(addr, (struct sockaddr *)&ss, &len);
	if (bind(sock, (struct sockaddr *)&ss, len)) {
		printf("bind() failed: %s\n", strerror(errno));
		return 0;
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
		return 0;
	}

	/* create the struct to pass to the callback function */
	struct peer_info *p = malloc(sizeof(struct peer_info));
	p->base = base;
	p->ctx = ctx;
	p->ssl = p->bev = NULL;

	/* add it to the event loop */
	struct event *evt =
		event_new(base, sock, EV_READ | EV_PERSIST, server_recv, p);
	if (evt == NULL) {
		printf("event_new() failed\n");
		return 0;
	}
	event_add(evt, NULL);

	return 1;
}

/*
 * Creates a connection with a remote host.
 */

static int create_client(struct event_base *base, void *ctx, char *addr)
{
	/* create a new SSL object */
	void *ssl = NULL;
	if (!dtls_instance_init(&ssl, ctx)) {
		return 0;
	}

	/* create client socket */
	struct bufferevent *bev = bufferevent_openssl_socket_new
		(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);

	/* create the struct to pass to the callback function */
	struct peer_info *p = malloc(sizeof(struct peer_info));
	p->base = base;
	p->ctx = ctx;
	p->ssl = ssl;
	p->bev = bev;

	bufferevent_setcb(bev, client_recv, NULL, client_event, p);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	/* connect to the address */
	struct sockaddr_storage ss;
	int len = sizeof(struct sockaddr_storage);
	evutil_parse_sockaddr_port(addr, (struct sockaddr *)&ss, &len);
	if (bufferevent_socket_connect(bev, (struct sockaddr *)&ss, len) < 0) {
		printf("bufferevent_socket_connect() failed\n");
		return 0;
	}

	return 1;
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

	/* create the DTLS context */
	void *ctx = NULL;
	if (!dtls_global_init(&ctx, priv, pub)) {
		return 0;
	}

	/* create the server */
	int port;
	if (!create_server(base, ctx, addr, &port)) {
		return 0;
	}
	printf("Using UDP port %hu\n", port);

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
		create_client(base, ctx, "127.0.0.1:63306");
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
