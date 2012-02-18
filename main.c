#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <event2/event.h>

/*
 *  Callback function that is called when a packet is received.
 */

void receivedDatagram(evutil_socket_t sock, short eventType, void* param)
{
	
}

/*
 * Initializes the only socket we'll use for talking to external hosts.
 */

int startNode(struct event_base* base)
{
	/* Create a UDP socket. */

	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed.\n");
		return 1;
	}
	evutil_make_socket_nonblocking(sock);

	/* Bind the socket. */

	struct sockaddr_storage addr;
	int len = sizeof(addr);
	evutil_parse_sockaddr_port("127.0.0.1", (struct sockaddr*)&addr, &len);
	if (bind(sock, (struct sockaddr*)&addr, len)) {
		printf("bind() failed. %s\n", strerror(errno));
		return 1;
	}

	/* Announce the port it is running on. */

	getsockname(sock, (struct sockaddr*)&addr, &len);
	printf("Using port %d...\n", ntohs(((struct sockaddr_in*)&addr)->sin_port));

	/* Add it to the event loop. */

	struct event* evt =
		event_new(base, sock, EV_READ | EV_PERSIST, receivedDatagram, NULL);
	if (evt == NULL) {
		printf("event_new() failed.\n");
		return 1;
	}
	event_add(evt, NULL);

	return 0;
}

/*
 * Initializes and begins listening for events.
 */

int main(int argc, char** argv)
{
	/* Determine if we are running in test mode. */

	int nodeCount = 1;
	while (argc > 0) {
		argc--;
		if (!strcmp(argv[argc], "--test"))
			nodeCount = 10;
	}

	/* Start the node(s) and enter the event loop. */

	struct event_base* base = event_base_new();
	for (; nodeCount > 0; nodeCount--) {
		if (startNode(base))
			return 1;
	}
	event_base_dispatch(base);
}
