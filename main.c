#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <event2/event.h>

void handleEvent(evutil_socket_t sock, short eventType, void* param)
{
	
}

int main()
{
	struct event_base* base = event_base_new();

	/* Create a UDP socket. */

	evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		printf("socket() failed.\n");
		return 1;
	}
	evutil_make_socket_nonblocking(sock);

	/* Bind the socket to a port. */

	struct sockaddr_storage addr;
	int len = sizeof(addr);
	evutil_parse_sockaddr_port
		("127.0.0.1:4707", (struct sockaddr*) &addr, &len);
	if (bind(sock, (struct sockaddr*) &addr, len)) {
		printf("bind() failed. %s\n", strerror(errno));
		return 1;
	}

	/* Add it to the event loop. */

	struct event* evt =
		event_new(base, sock, EV_READ | EV_PERSIST, handleEvent, NULL);
	event_add(evt, NULL);

	event_base_dispatch(base);
}
