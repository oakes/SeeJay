#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <event2/event.h>

#include "crypto.h"
#include "util.h"

#define PRIVATE_KEY "private.pem"
#define PUBLIC_KEY "public.pem"

/*
 * Callback function that is called when a packet is received.
 */

static void received_data(evutil_socket_t sock, short eventType, void* param)
{
	
}

/*
 * Gets the crypto key and initializes the UDP socket.
 */

static int start_node(struct event_base* base, int node_num)
{
	/* create or load the key */

	void *key = NULL;
	if (node_num > 1 && create_key(&key) < 0) {
		return -1;
	}
	else if (!file_exists(PRIVATE_KEY)) {
		if (create_key(&key) < 0 ||
			write_key(key, PRIVATE_KEY, PUBLIC_KEY) < 0)
		{
			return -1;
		}
	}
	else if (read_key(&key, PRIVATE_KEY) < 0) {
		return -1;
	}

	/* create a UDP socket */

	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed\n");
		return -1;
	}
	evutil_make_socket_nonblocking(sock);

	/* bind the socket */

	struct sockaddr_storage addr;
	int len = sizeof(addr);
	evutil_parse_sockaddr_port("127.0.0.1", (struct sockaddr*)&addr, &len);
	if (bind(sock, (struct sockaddr*)&addr, len)) {
		printf("bind() failed: %s\n", strerror(errno));
		return -1;
	}

	/* announce the port it is running on */

	getsockname(sock, (struct sockaddr*)&addr, &len);
	printf("Using port %d...\n", ntohs(((struct sockaddr_in*)&addr)->sin_port));

	/* add it to the event loop */

	struct event *evt =
		event_new(base, sock, EV_READ | EV_PERSIST, received_data, NULL);
	if (evt == NULL) {
		printf("event_new() failed\n");
		return -1;
	}
	event_add(evt, NULL);

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
		if (!strcmp(argv[argc], "--test"))
			count = 10;
	}

	/* start the node(s) and enter the event loop */

	struct event_base *base = event_base_new();
	for (; count > 0; count--) {
		if (start_node(base, count) < 0)
			return 1;
	}
	event_base_dispatch(base);
}
