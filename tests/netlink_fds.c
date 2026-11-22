/* Scenarios of test-738b8dfc.sh: NETLINK_ROUTE sockets used the way the
 * kernel allows, from several threads, through copies of their
 * descriptor, across fork(2) and execve(2).  Each request is a dump of
 * the addresses, which ends with NLMSG_DONE.  Exits with 125 when the
 * host has no netlink at all.  */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define FAIL(...) do {				\
	fprintf(stderr, "%s: ", mode);		\
	fprintf(stderr, __VA_ARGS__);		\
	fprintf(stderr, "\n");			\
	exit(1);				\
} while (0)

static const char *mode = "";
static const char *self;

static int nl_open(int flags)
{
	struct sockaddr_nl address = { .nl_family = AF_NETLINK };
	struct timeval timeout = { 2, 0 };
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | flags, NETLINK_ROUTE);
	if (fd < 0)
		exit(125);

	if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0)
		FAIL("bind(%d): %s", fd, strerror(errno));

	/* Fail instead of hanging when no reply ever comes.  */
	(void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	return fd;
}

struct request {
	struct nlmsghdr header;
	struct ifaddrmsg message;
};

static struct request *request(unsigned int seq)
{
	static struct request request;

	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len   = sizeof(request);
	request.header.nlmsg_type  = RTM_GETADDR;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.header.nlmsg_seq   = seq;
	return &request;
}

static void nl_request(int fd, unsigned int seq)
{
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };

	if (sendto(fd, request(seq), sizeof(struct request), 0,
		   (struct sockaddr *) &kernel, sizeof(kernel)) < 0)
		FAIL("sendto(%d): %s", fd, strerror(errno));
}

static unsigned int port_id(int fd)
{
	struct sockaddr_nl address = { 0 };
	socklen_t size = sizeof(address);

	if (getsockname(fd, (struct sockaddr *) &address, &size) < 0)
		FAIL("getsockname(%d): %s", fd, strerror(errno));
	if (address.nl_family != AF_NETLINK)
		FAIL("getsockname(%d): family %d", fd, address.nl_family);
	return address.nl_pid;
}

/* Read the reply to the request @seq until NLMSG_DONE.  Return -1 if
 * nothing is pending, 0 otherwise.  Every message has to be sent to
 * the port the socket is bound to, as callers check (Go, glibc).  */
static int nl_reply(int fd, unsigned int seq)
{
	char buffer[16384] __attribute__((aligned(8)));
	unsigned int port = port_id(fd);
	int first;

	for (first = 1; ; first = 0) {
		struct nlmsghdr *header = (struct nlmsghdr *) buffer;
		ssize_t size;

		size = recv(fd, buffer, sizeof(buffer), 0);
		if (size < 0 && first && (errno == EAGAIN || errno == EWOULDBLOCK))
			return -1;
		if (size < 0)
			FAIL("recv(%d): %s", fd, strerror(errno));

		for (; NLMSG_OK(header, size); header = NLMSG_NEXT(header, size)) {
			if (header->nlmsg_seq != seq)
				FAIL("fd %d: sequence %u instead of %u", fd, header->nlmsg_seq, seq);
			if (header->nlmsg_pid != port)
				FAIL("fd %d: port %u instead of %u", fd, header->nlmsg_pid, port);
			if (header->nlmsg_type == NLMSG_ERROR)
				FAIL("fd %d: NLMSG_ERROR", fd);
			if (header->nlmsg_type == NLMSG_DONE)
				return 0;
		}
	}
}

static bool nothing_pending(int fd)
{
	char buffer[64];

	return recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT) < 0
	    && (errno == EAGAIN || errno == EWOULDBLOCK);
}

static void round_trip(int send_fd, int recv_fd, unsigned int seq)
{
	nl_request(send_fd, seq);
	if (nl_reply(recv_fd, seq) < 0)
		FAIL("no reply on fd %d to the request on fd %d", recv_fd, send_fd);
}

/* Check the descriptor @fd works as the UDP socket it is.  */
static void check_udp(int fd)
{
	struct sockaddr_in address = { .sin_family = AF_INET };
	struct sockaddr_in bound = { 0 };
	socklen_t size = sizeof(bound);

	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0)
		FAIL("UDP bind(%d): %s", fd, strerror(errno));
	if (getsockname(fd, (struct sockaddr *) &bound, &size) < 0)
		FAIL("UDP getsockname(%d): %s", fd, strerror(errno));
	if (bound.sin_family != AF_INET || bound.sin_port == 0)
		FAIL("UDP fd %d: family %d, port %d", fd, bound.sin_family, ntohs(bound.sin_port));
}

/* Make a UDP socket with the descriptor @fd, the lowest free one or
 * not, and check it.  */
static void check_udp_at(int fd)
{
	int fds[64];
	int count = 0;
	int udp;

	while ((udp = socket(AF_INET, SOCK_DGRAM, 0)) >= 0 && udp != fd && count < 64)
		fds[count++] = udp;
	if (udp != fd)
		FAIL("no UDP socket at fd %d", fd);
	while (count > 0)
		close(fds[--count]);

	check_udp(fd);
	close(fd);
}

/* A thread other than the one that runs main(), which runs one job at
 * a time on request.  It exists before any socket.  */

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static void (*job)(void);

static void *worker(void *unused)
{
	(void) unused;

	pthread_mutex_lock(&lock);
	for (;;) {
		while (job == NULL)
			pthread_cond_wait(&cond, &lock);
		pthread_mutex_unlock(&lock);

		job();

		pthread_mutex_lock(&lock);
		job = NULL;
		pthread_cond_broadcast(&cond);
	}
	return NULL;
}

static void in_worker(void (*function)(void))
{
	pthread_mutex_lock(&lock);
	job = function;
	pthread_cond_broadcast(&cond);
	while (job != NULL)
		pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);
}

static void start_worker(void)
{
	pthread_t thread;

	if (pthread_create(&thread, NULL, worker, NULL) != 0)
		FAIL("pthread_create");
}

static int fds[12];
static int nb_fds;
static int peeked;

static void read_reply_1(void)	{ if (nl_reply(fds[0], 1) < 0) FAIL("no reply in the other thread"); }
static void request_2(void)	{ nl_request(fds[0], 2); }
static void peek_reply(void)	{ peeked = recv(fds[0], NULL, 0, MSG_PEEK | MSG_TRUNC); }
static void check_udp_0(void)	{ check_udp_at(fds[0]); }
static void open_all(void)	{ for (nb_fds = 0; nb_fds < 12; nb_fds++) fds[nb_fds] = nl_open(SOCK_CLOEXEC); }

static void threads(void)
{
	char buffer[16384] __attribute__((aligned(8)));
	int i;

	start_worker();

	/* Issue #425: a thread reads the reply to the request another
	 * one sent, on a socket opened after the thread was created.  */
	fds[0] = nl_open(SOCK_CLOEXEC);
	nl_request(fds[0], 1);
	in_worker(read_reply_1);

	in_worker(request_2);
	if (nl_reply(fds[0], 2) < 0)
		FAIL("no reply to the request of the other thread");

	/* The size of the pending datagram, as iproute2 asks.  */
	nl_request(fds[0], 3);
	in_worker(peek_reply);
	if (peeked <= 0)
		FAIL("MSG_PEEK in the other thread: %d", peeked);
	if (recv(fds[0], buffer, sizeof(buffer), 0) != peeked)
		FAIL("the datagram isn't the size MSG_PEEK said");
	(void) nl_reply(fds[0], 3);

	/* A socket closed by one thread is closed for all of them, so
	 * its descriptor may be reused for anything.  */
	close(fds[0]);
	in_worker(check_udp_0);

	/* More sockets than PRoot used to track per process.  */
	in_worker(open_all);
	for (i = 0; i < nb_fds; i++)
		round_trip(fds[i], fds[i], 100 + i);
}

static void copies(void)
{
	int fd = nl_open(SOCK_CLOEXEC);
	int copy[5];
	int udp;
	int i;

	copy[0] = dup(fd);
	copy[1] = fcntl(fd, F_DUPFD, 20);
	copy[2] = fcntl(fd, F_DUPFD_CLOEXEC, 30);
	copy[3] = dup2(fd, 40);
	copy[4] = dup3(fd, 50, O_CLOEXEC);
	for (i = 0; i < 5; i++) {
		if (copy[i] < 0)
			FAIL("copy %d: %s", i, strerror(errno));
		if (port_id(copy[i]) != port_id(fd))
			FAIL("copy %d: another port", i);
		round_trip(copy[i], fd, 10 + i);
		round_trip(fd, copy[i], 20 + i);
	}

	/* The socket lives as long as a descriptor refers to it.  */
	close(fd);
	round_trip(copy[0], copy[4], 30);
	for (i = 0; i < 4; i++)
		close(copy[i]);
	round_trip(copy[4], copy[4], 31);

	/* Descriptors replaced by another socket.  */
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (dup2(udp, copy[4]) != copy[4])
		FAIL("dup2: %s", strerror(errno));
	check_udp(copy[4]);

	fd = nl_open(0);
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (dup3(udp, fd, 0) != fd)
		FAIL("dup3: %s", strerror(errno));
	check_udp(fd);
}

static void forks(void)
{
	int fd = nl_open(0);
	int status;
	pid_t pid;

	/* A child reads the reply to the request of its parent.  */
	nl_request(fd, 1);
	pid = fork();
	if (pid == 0) {
		if (nl_reply(fd, 1) < 0)
			FAIL("no reply in the child");
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		exit(1);
	if (!nothing_pending(fd))
		FAIL("the parent got the reply the child read already");

	/* And the other way round.  */
	pid = fork();
	if (pid == 0) {
		nl_request(fd, 2);
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		exit(1);
	if (nl_reply(fd, 2) < 0)
		FAIL("no reply in the parent");
}

/* Requests sent without the netlink syscalls, as busybox does.  */
static void writes(void)
{
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct iovec iov[2];
	int fd = nl_open(0);

	if (write(fd, request(1), sizeof(struct request)) != sizeof(struct request))
		FAIL("write(%d): %s", fd, strerror(errno));
	if (nl_reply(fd, 1) < 0)
		FAIL("no reply to write(2)");

	iov[0].iov_base = request(2);
	iov[0].iov_len  = sizeof(struct nlmsghdr);
	iov[1].iov_base = (char *) request(2) + sizeof(struct nlmsghdr);
	iov[1].iov_len  = sizeof(struct request) - sizeof(struct nlmsghdr);
	if (writev(fd, iov, 2) != sizeof(struct request))
		FAIL("writev(%d): %s", fd, strerror(errno));
	if (nl_reply(fd, 2) < 0)
		FAIL("no reply to writev(2)");

	/* Connected after it was bound, still answered.  */
	if (connect(fd, (struct sockaddr *) &kernel, sizeof(kernel)) < 0)
		FAIL("connect(%d) after bind(2): %s", fd, strerror(errno));
	round_trip(fd, fd, 3);
	if (write(fd, request(4), sizeof(struct request)) != sizeof(struct request))
		FAIL("write(%d): %s", fd, strerror(errno));
	if (nl_reply(fd, 4) < 0)
		FAIL("no reply to write(2) after connect(2)");

	/* Connected to the kernel rather than bound.  */
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0 || connect(fd, (struct sockaddr *) &kernel, sizeof(kernel)) < 0)
		FAIL("connect(%d): %s", fd, strerror(errno));
	if (write(fd, request(5), sizeof(struct request)) != sizeof(struct request))
		FAIL("write(%d): %s", fd, strerror(errno));
	if (nl_reply(fd, 5) < 0)
		FAIL("no reply to write(2) on a socket never bound");
}

static char *exec_argv[5];

static void exec_check(void)
{
	execv("/proc/self/exe", exec_argv);
	FAIL("execv: %s", strerror(errno));
}

/* execve(2) closes the close-on-exec descriptors.  The loader of PRoot
 * reuses the lowest one, so another one is closed below the socket.  */
static void execs(bool from_thread)
{
	static char kept[16], closed[16];
	int other = open("/dev/null", O_RDONLY | O_CLOEXEC);

	(void) other;
	snprintf(kept, sizeof(kept), "%d", nl_open(0));
	snprintf(closed, sizeof(closed), "%d", nl_open(SOCK_CLOEXEC));

	exec_argv[0] = (char *) self;
	exec_argv[1] = "exec-check";
	exec_argv[2] = kept;
	exec_argv[3] = closed;
	exec_argv[4] = NULL;

	if (!from_thread)
		exec_check();

	start_worker();
	in_worker(exec_check);
}

int main(int argc, char *argv[])
{
	self = argv[0];
	mode = argc > 1 ? argv[1] : "";

	if (strcmp(mode, "threads") == 0)
		threads();
	else if (strcmp(mode, "copies") == 0)
		copies();
	else if (strcmp(mode, "forks") == 0)
		forks();
	else if (strcmp(mode, "writes") == 0)
		writes();
	else if (strcmp(mode, "exec") == 0)
		execs(false);
	else if (strcmp(mode, "thread-exec") == 0)
		execs(true);
	else if (strcmp(mode, "exec-check") == 0 && argc == 4) {
		round_trip(atoi(argv[2]), atoi(argv[2]), 1);
		check_udp_at(atoi(argv[3]));
	}
	else {
		fprintf(stderr, "usage: %s threads|copies|forks|writes|exec|thread-exec\n", argv[0]);
		return 2;
	}

	return 0;
}
