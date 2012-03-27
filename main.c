#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include "crypto.h"
#include "util.h"

#define PRIV_FILE "private.pem"
#define PUB_FILE "public.pem"
#define CONFIG_FILE  "seejay.conf"

/*
 * Callback function when receiving data.
 */

static void on_read(struct bufferevent *bev, void *ctx)
{
	printf("on_read()\n");
}

/*
 * Callback function when writing data.
 */

static void on_write(struct bufferevent *bev, void *ctx)
{
	printf("on_write()\n");
}

/*
 * Callback function when misc events happen.
 */

static void on_event(struct bufferevent *bev, short what, void *ctx)
{
	printf("on_event()\n");
}

/*
 * Callback function when connection is accepted.
 */

static void on_accept
	(struct evconnlistener *serv,
	evutil_socket_t sock,
	struct sockaddr *addr,
	int addr_len,
	void *ctx)
{
	printf("on_accept()\n");
}

/*
 * Creates a new event with the given socket.
 */

static struct bufferevent * create_event
	(struct event_base *base, void *ctx, evutil_socket_t sock)
{
	void *ssl = NULL;
	if (!tls_local_init(&ssl, ctx)) {
		return NULL;
	}
	struct bufferevent *bev = bufferevent_openssl_socket_new(base, sock, ssl,
		sock >= 0 ? BUFFEREVENT_SSL_ACCEPTING : BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	bufferevent_setcb(bev, on_read, on_write, on_event, ctx);
	return bev;
}

/*
 * Creates and binds a socket to accept packets.
 */

static evutil_socket_t create_socket(char *addr, int *port)
{
	/* create a socket */
	evutil_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
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
 * Gets the crypto keys and initializes the server.
 */

static int start_node(struct event_base *base, int last_port)
{
	/* create or load the keys */
	void *priv = NULL, *pub = NULL;
	if (last_port > 0 || !file_exists(PRIV_FILE)) {
		if (!create_private_key(&priv) ||
			!create_public_key(&pub, priv))
		{
			return 0;
		}
		if (last_port == 0) {
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
	if (last_port == 0 && file_exists(CONFIG_FILE)) {
		if (!read_config(CONFIG_FILE, "tcpsrv", addr)) {
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
	printf("Using port %hu\n", port);

	/* create the context */
	void *ctx = NULL;
	if (!tls_global_init(&ctx, priv, pub)) {
		return 0;
	}

	/* add it to the event loop */
	struct evconnlistener *conn = evconnlistener_new(base, on_accept, ctx,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024, sock);

	/* write the config file if necessary */
	if (last_port == 0 && !file_exists(CONFIG_FILE)) {
		FILE *file = fopen(CONFIG_FILE, "w");
		if (fprintf(file, "# Port to accept peers on (forward it!)\n") < 0 ||
			fprintf(file, "tcpsrv\t\t\t%s:%hu\n\n", addr, port) < 0 ||
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

	/* test connection if necessary */
	if (last_port > 0) {
		struct bufferevent *bev = create_event(base, ctx, -1);

		sprintf(addr, "127.0.0.1:%d", last_port);
		struct sockaddr_storage ss;
		int len = sizeof(ss);

		evutil_parse_sockaddr_port(addr, (struct sockaddr *)&ss, &len);
		if (bufferevent_socket_connect(bev, (struct sockaddr *)&ss, len)) {
			return 0;
		}
	}

	return port;
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
	int port = 0;
	for (; count > 0; count--) {
		if (!(port = start_node(base, port))) {
			return 1;
		}
	}
	event_base_dispatch(base);
}
