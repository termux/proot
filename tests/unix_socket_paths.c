#define _GNU_SOURCE /* struct mmsghdr, sendmmsg(2), */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Usage:
 *
 *     unix_socket_paths scenarios <dir> [<name>]
 *     unix_socket_paths serve|client <dir> <name>
 *
 * The scenarios check that a socket bound to a path in <dir> behaves
 * as any other file there, as the kernel makes it, and that connect(2)
 * and the destinations of sendto(2) and the like leave the files they
 * name as they are.  The socket <dir>/<name> is bound and connected to
 * as well, if <name> is given.  A line is printed for each check that
 * fails.
 *
 * serve binds a socket to <name> in <dir>, says "ready" once it
 * listens, then waits for a client to say "ping".  client says it.  */

static int failures = 0;

#define CHECK(condition, ...) do {					\
		if (!(condition)) {					\
			printf("line %d: ", __LINE__);			\
			printf(__VA_ARGS__);				\
			printf(" (%s)\n", strerror(errno));		\
			failures++;					\
		}							\
	} while (0)

static socklen_t make_address(struct sockaddr_un *address, const char *path)
{
	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(address->sun_path)) {
		printf("%s: too long\n", path);
		exit(2);
	}
	strcpy(address->sun_path, path);
	return sizeof(*address);
}

static int bind_to(int fd, const char *path)
{
	struct sockaddr_un address;
	socklen_t size = make_address(&address, path);
	return bind(fd, (struct sockaddr *) &address, size);
}

static int connect_to(int fd, const char *path)
{
	struct sockaddr_un address;
	socklen_t size = make_address(&address, path);
	return connect(fd, (struct sockaddr *) &address, size);
}

/* The return value of the call that is expected to fail with @error.  */
static int fails_with(int status, int error)
{
	return status < 0 && errno == error;
}

static int is_listed(const char *dir, const char *name)
{
	struct dirent *entry;
	int found = 0;
	DIR *stream;

	stream = opendir(dir);
	if (stream == NULL)
		return 0;

	while ((entry = readdir(stream)) != NULL)
		if (strcmp(entry->d_name, name) == 0)
			found = 1;

	closedir(stream);
	return found;
}

static int has_type(const char *path, mode_t type, off_t size)
{
	struct stat statl;

	if (lstat(path, &statl) < 0)
		return 0;

	return (statl.st_mode & S_IFMT) == type && (type == S_IFSOCK || statl.st_size == size);
}

static int create_file(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		return -1;

	if (write(fd, "keep", 4) != 4) {
		close(fd);
		return -1;
	}

	return close(fd);
}

/* Whether the address of the socket @fd, or of its peer, is @path.  */
static int is_named(int fd, int peer, const char *path)
{
	struct sockaddr_un address;
	socklen_t size = sizeof(address);
	int status;

	memset(&address, 0, sizeof(address));
	status = peer
		? getpeername(fd, (struct sockaddr *) &address, &size)
		: getsockname(fd, (struct sockaddr *) &address, &size);
	if (status < 0 || size <= offsetof(struct sockaddr_un, sun_path))
		return 0;

	return size == offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1
		&& strcmp(address.sun_path, path) == 0;
}

static void check_stream(const char *dir)
{
	char path[PATH_MAX];
	char buffer[4];
	int server;
	int client;
	int peer;
	int fd;

	snprintf(path, sizeof(path), "%s/stream", dir);

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	client = socket(AF_UNIX, SOCK_STREAM, 0);

	CHECK(bind_to(server, path) == 0, "bind %s", path);
	CHECK(is_listed(dir, "stream"), "%s not listed", path);
	CHECK(has_type(path, S_IFSOCK, 0), "%s not a socket", path);
	CHECK(is_named(server, 0, path), "getsockname %s", path);
	CHECK(listen(server, 4) == 0, "listen %s", path);

	CHECK(connect_to(client, path) == 0, "connect %s", path);
	CHECK(is_named(client, 1, path), "getpeername %s", path);

	peer = accept(server, NULL, NULL);
	CHECK(peer >= 0, "accept %s", path);
	CHECK(write(client, "data", 4) == 4 && read(peer, buffer, 4) == 4, "data through %s", path);

	close(peer);
	close(client);
	close(server);

	/* The socket is removed with the directory, as rm -r does it:
	 * nothing is left of it, the same path can be a regular file.  */
	fd = open(dir, O_RDONLY | O_DIRECTORY);
	CHECK(unlinkat(fd, "stream", 0) == 0, "unlinkat %s", path);
	close(fd);

	CHECK(rmdir(dir) == 0, "rmdir %s", dir);
	CHECK(mkdir(dir, 0755) == 0, "mkdir %s", dir);
	CHECK(create_file(path) == 0, "create %s", path);
	CHECK(is_listed(dir, "stream"), "%s not listed", path);
	CHECK(unlink(path) == 0, "unlink %s", path);
}

static void check_existing(const char *dir)
{
	char path[PATH_MAX];
	int fd;

	/* A file stays as it is.  */
	snprintf(path, sizeof(path), "%s/file", dir);
	CHECK(create_file(path) == 0, "create %s", path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fails_with(bind_to(fd, path), EADDRINUSE), "bind %s", path);
	close(fd);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fails_with(connect_to(fd, path), ECONNREFUSED), "connect %s", path);
	close(fd);

	CHECK(has_type(path, S_IFREG, 4), "%s changed", path);
	CHECK(unlink(path) == 0, "unlink %s", path);

	/* Nothing is made where nothing is.  */
	snprintf(path, sizeof(path), "%s/missing/socket", dir);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fails_with(bind_to(fd, path), ENOENT), "bind %s", path);
	close(fd);

	snprintf(path, sizeof(path), "%s/missing", dir);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fails_with(connect_to(fd, path), ENOENT), "connect %s", path);
	close(fd);

	CHECK(create_file(path) == 0, "create %s", path);
	CHECK(is_listed(dir, "missing"), "%s not listed", path);
	CHECK(unlink(path) == 0, "unlink %s", path);

	snprintf(path, sizeof(path), "%s/slash/", dir);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fails_with(bind_to(fd, path), ENOENT), "bind %s", path);
	close(fd);

	/* Nor by a socket bound already.  */
	snprintf(path, sizeof(path), "%s/once", dir);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(bind_to(fd, path) == 0, "bind %s", path);

	snprintf(path, sizeof(path), "%s/twice", dir);
	CHECK(fails_with(bind_to(fd, path), EINVAL), "bind %s", path);
	close(fd);

	CHECK(create_file(path) == 0, "create %s", path);
	CHECK(is_listed(dir, "twice"), "%s not listed", path);
	CHECK(unlink(path) == 0, "unlink %s", path);

	snprintf(path, sizeof(path), "%s/once", dir);
	CHECK(unlink(path) == 0, "unlink %s", path);
}

static void check_datagrams(const char *dir)
{
	struct sockaddr_un destination;
	struct sockaddr_un source;
	struct mmsghdr messages[2];
	struct msghdr message;
	struct iovec iovec;
	char server_path[PATH_MAX];
	char client_path[PATH_MAX];
	socklen_t source_size;
	char buffer[4];
	int server;
	int client;

	snprintf(server_path, sizeof(server_path), "%s/server", dir);
	snprintf(client_path, sizeof(client_path), "%s/client", dir);

	server = socket(AF_UNIX, SOCK_DGRAM, 0);
	client = socket(AF_UNIX, SOCK_DGRAM, 0);

	CHECK(bind_to(server, server_path) == 0, "bind %s", server_path);
	CHECK(bind_to(client, client_path) == 0, "bind %s", client_path);

	make_address(&destination, server_path);
	CHECK(sendto(client, "a", 1, 0, (struct sockaddr *) &destination,
		     sizeof(destination)) == 1, "sendto %s", server_path);

	/* The reply goes to the source the kernel reports.  */
	source_size = sizeof(source);
	memset(&source, 0, sizeof(source));
	CHECK(recvfrom(server, buffer, 1, MSG_DONTWAIT, (struct sockaddr *) &source,
		       &source_size) == 1, "recvfrom %s", server_path);
	CHECK(sendto(server, "b", 1, 0, (struct sockaddr *) &source, source_size) == 1,
	      "reply from %s", server_path);
	CHECK(recv(client, buffer, 1, MSG_DONTWAIT) == 1, "reply to %s", client_path);

	iovec.iov_base = "c";
	iovec.iov_len  = 1;
	memset(&message, 0, sizeof(message));
	message.msg_name    = &destination;
	message.msg_namelen = sizeof(destination);
	message.msg_iov     = &iovec;
	message.msg_iovlen  = 1;
	CHECK(sendmsg(client, &message, 0) == 1, "sendmsg %s", server_path);
	CHECK(recv(server, buffer, 1, MSG_DONTWAIT) == 1, "sendmsg to %s", server_path);

	memset(messages, 0, sizeof(messages));
	messages[0].msg_hdr = message;
	messages[1].msg_hdr = message;
	CHECK(sendmmsg(client, messages, 2, 0) == 2
	      && messages[0].msg_len == 1 && messages[1].msg_len == 1, "sendmmsg %s", server_path);
	CHECK(recv(server, buffer, 1, MSG_DONTWAIT) == 1
	      && recv(server, buffer, 1, MSG_DONTWAIT) == 1, "sendmmsg to %s", server_path);

	close(client);
	close(server);

	CHECK(unlink(server_path) == 0, "unlink %s", server_path);
	CHECK(unlink(client_path) == 0, "unlink %s", client_path);
}

static void check_relative(const char *dir)
{
	char cwd[PATH_MAX];
	char path[PATH_MAX];
	int server;
	int client;

	if (getcwd(cwd, sizeof(cwd)) == NULL || chdir(dir) < 0) {
		CHECK(0, "chdir %s", dir);
		return;
	}

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(bind_to(server, "relative") == 0, "bind relative");
	CHECK(listen(server, 4) == 0, "listen relative");
	CHECK(is_listed(".", "relative"), "relative not listed");

	/* The socket can be found once renamed.  */
	CHECK(rename("relative", "renamed") == 0, "rename relative");

	client = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect_to(client, "renamed") == 0, "connect renamed");
	close(client);

	snprintf(path, sizeof(path), "%s/renamed", dir);
	client = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect_to(client, path) == 0, "connect %s", path);
	close(client);

	close(server);
	CHECK(unlink("renamed") == 0, "unlink renamed");
	CHECK(chdir(cwd) == 0, "chdir %s", cwd);
}

static void check_name(const char *dir, const char *name)
{
	char path[PATH_MAX];
	int server;
	int client;

	snprintf(path, sizeof(path), "%s/%s", dir, name);

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	client = socket(AF_UNIX, SOCK_STREAM, 0);

	CHECK(bind_to(server, path) == 0, "bind %s", path);
	CHECK(is_named(server, 0, path), "getsockname %s", path);
	CHECK(listen(server, 4) == 0, "listen %s", path);
	CHECK(connect_to(client, path) == 0, "connect %s", path);

	close(client);
	close(server);

	CHECK(unlink(path) == 0, "unlink %s", path);
}

static int serve(const char *name)
{
	char buffer[4];
	int server;
	int peer;

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind_to(server, name) < 0 || listen(server, 1) < 0) {
		perror("bind");
		return 1;
	}

	printf("ready\n");
	fflush(stdout);

	peer = accept(server, NULL, NULL);
	if (peer < 0 || read(peer, buffer, 4) != 4 || memcmp(buffer, "ping", 4) != 0) {
		perror("accept");
		return 1;
	}

	return 0;
}

static int client(const char *name)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (connect_to(fd, name) < 0 || write(fd, "ping", 4) != 4) {
		perror("connect");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char dir[PATH_MAX];

	alarm(60);

	if (argc == 4 && strcmp(argv[1], "serve") == 0)
		return chdir(argv[2]) == 0 ? serve(argv[3]) : 1;

	if (argc == 4 && strcmp(argv[1], "client") == 0)
		return chdir(argv[2]) == 0 ? client(argv[3]) : 1;

	if ((argc != 3 && argc != 4) || strcmp(argv[1], "scenarios") != 0) {
		fprintf(stderr, "usage: %s scenarios <dir> [<name>]\n", argv[0]);
		fprintf(stderr, "       %s serve|client <dir> <name>\n", argv[0]);
		return 2;
	}

	snprintf(dir, sizeof(dir), "%s/sockets", argv[2]);
	if (mkdir(dir, 0755) < 0) {
		perror("mkdir");
		return 2;
	}

	check_stream(dir);
	check_existing(dir);
	check_datagrams(dir);
	check_relative(dir);

	if (argc == 4)
		check_name(dir, argv[3]);

	CHECK(rmdir(dir) == 0, "rmdir %s", dir);

	return failures == 0 ? 0 : 1;
}
