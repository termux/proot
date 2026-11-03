/* Threads share their file descriptors, so a NETLINK_ROUTE socket
 * that one thread opens must work from another one: a request sent by
 * one thread gets its answer in the other.  When the host blocks
 * AF_NETLINK, PRoot emulates such sockets; it used to know a socket
 * only in the thread that opened it, and a recv(2) from another thread
 * then blocked for ever (Go programs hit this in net.Interfaces()).
 *
 * The worker thread is started before the socket exists, as Go does
 * with the threads it moves goroutines between.  */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int fd = -1;
static int to_worker[2];
static int to_main[2];

static void timeout(int signo)
{
	(void) signo;
	static const char message[] = "recv(2) from another thread blocked\n";
	(void) write(2, message, sizeof(message) - 1);
	_exit(EXIT_FAILURE);
}

static int request(unsigned int seq)
{
	struct {
		struct nlmsghdr  nlh;
		struct ifaddrmsg ifa;
	} req;
	struct sockaddr_nl kernel;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = sizeof(req);
	req.nlh.nlmsg_type  = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq   = seq;
	req.ifa.ifa_family  = AF_UNSPEC;

	memset(&kernel, 0, sizeof(kernel));
	kernel.nl_family = AF_NETLINK;

	return sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &kernel, sizeof(kernel)) == sizeof(req) ? 0 : -1;
}

/* Reads the whole dump: 0 when it ends with NLMSG_DONE.  */
static int answer(unsigned int seq)
{
	static char buffer[16384] __attribute__((aligned(NLMSG_ALIGNTO)));

	for (;;) {
		ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
		struct nlmsghdr *nlh;

		if (length <= 0)
			return -1;

		for (nlh = (struct nlmsghdr *) buffer; NLMSG_OK(nlh, length); nlh = NLMSG_NEXT(nlh, length)) {
			if (nlh->nlmsg_seq != seq || nlh->nlmsg_type == NLMSG_ERROR)
				return -1;
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
		}
	}
}

static void *worker(void *unused)
{
	char step;
	(void) unused;

	/* First: read the answer to the request of the main thread.  */
	if (read(to_worker[0], &step, 1) != 1 || answer(1) < 0)
		step = 'x';
	/* Then: send a request, the main thread reads the answer.  */
	else if (request(2) < 0)
		step = 'x';

	(void) write(to_main[1], &step, 1);
	return NULL;
}

int main(void)
{
	struct sockaddr_nl local;
	pthread_t thread;
	char step = 'g';

	if (pipe(to_worker) < 0 || pipe(to_main) < 0) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&thread, NULL, worker, NULL) != 0) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		exit(125); /* No netlink at all here, nothing to test.  */

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	signal(SIGALRM, timeout);
	alarm(10);

	if (request(1) < 0) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}

	if (write(to_worker[1], &step, 1) != 1 || read(to_main[0], &step, 1) != 1 || step == 'x') {
		fprintf(stderr, "the worker thread failed\n");
		exit(EXIT_FAILURE);
	}

	if (answer(2) < 0) {
		fprintf(stderr, "no answer to the request of the worker thread\n");
		exit(EXIT_FAILURE);
	}

	pthread_join(thread, NULL);
	exit(EXIT_SUCCESS);
}
