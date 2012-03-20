#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/bufferevent.h>

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
 * Callback for receiving packets.
 */

static void on_read(struct bufferevent *bev, void *param)
{
	struct peer_info *p = param;

	char buf[1024];
	bufferevent_read(bev, buf, sizeof(buf));
	printf("on_read(): %s\n", buf);
}

/*
 * Callback for sending packets.
 */

static void on_write(struct bufferevent *bev, void *param)
{
	struct peer_info *p = param;

	printf("on_write()\n");
}

/*
 * Callback for socket events.
 */

static void on_event(struct bufferevent *bev, short events, void *params)
{
	
}

/*
 * Creates a new event with the given socket.
 */

static struct bufferevent * create_event
	(struct event_base *base, void *ctx, evutil_socket_t sock)
{
	/* create the struct to pass to the callback function */
	struct peer_info *p = malloc(sizeof(struct peer_info));
	p->base = base;
	p->ctx = ctx;
	p->ssl = NULL;

	/* create the bufferevent */
	struct bufferevent *bev =
		bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, on_read, on_write, on_event, p);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	return bev;
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

	/* add it to the event loop */
	struct bufferevent *bev = create_event(base, ctx, sock);

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
		struct bufferevent *bev2 = create_event(base, ctx, sock2);

		struct sockaddr_storage ss;
		int len = sizeof(struct sockaddr_storage);
		evutil_parse_sockaddr_port
			("127.0.0.1:63306", (struct sockaddr *)&ss, &len);
		if (bufferevent_socket_connect(bev2, (struct sockaddr *)&ss, len)) {
			printf("connect() failed\n");
			return 0;
		}

		bufferevent_write(bev2, "hello", sizeof("hello"));
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
