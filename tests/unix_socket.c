#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Bind a listening socket to the path given, connect to it through
 * this path, and exit without removing it.  */
int main(int argc, char *argv[])
{
	struct sockaddr_un sockaddr;
	int server;
	int client;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = AF_UNIX;

	if (argc != 2 || strlen(argv[1]) >= sizeof(sockaddr.sun_path)) {
		fprintf(stderr, "usage: %s <path>\n", argv[0]);
		return EXIT_FAILURE;
	}
	strcpy(sockaddr.sun_path, argv[1]);

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	client = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server < 0 || client < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	if (bind(server, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}

	if (listen(server, 1) < 0) {
		perror("listen");
		return EXIT_FAILURE;
	}

	if (connect(client, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
		perror("connect");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
