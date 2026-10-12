/* sendto(2), sendmsg(2) and sendmmsg(2) must deliver a datagram to a
 * named Unix domain socket of the guest, given by its absolute or
 * relative guest path, without changing the caller's structures.  A
 * reply to the sender address recvfrom(2) and recvmsg(2) report must
 * reach the sender, and a send interrupted by a signal handler must
 * succeed once restarted.  */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#define DIR       "/tmp/proot-test-571fb953"
#define RECEIVER  DIR "/r"
#define SENDER    DIR "/s"
#define MISSING   DIR "/missing"

static int failures = 0;

#define CHECK(condition) do {						\
	if (!(condition)) {						\
		fprintf(stderr, "line %d: %s failed (%s)\n",		\
			__LINE__, #condition, strerror(errno));		\
		failures++;						\
	}								\
} while (0)

static void make_address(struct sockaddr_un *address, const char *path)
{
	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	strcpy(address->sun_path, path);
}

static int new_socket(const char *path)
{
	struct sockaddr_un address;
	struct timeval timeout = { 2, 0 };
	int fd;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(125);
	}

	(void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	if (path == NULL)
		return fd;

	(void) unlink(path);
	make_address(&address, path);
	if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	return fd;
}

/* Check the next datagram @fd receives is @expected.  */
static void check_received(int fd, const char *expected, int line)
{
	char buffer[16] = { 0 };
	ssize_t status;

	status = recv(fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
	if (status < 0 || strcmp(buffer, expected) != 0) {
		fprintf(stderr, "line %d: expected \"%s\", got \"%s\" (%s)\n",
			line, expected, buffer, status < 0 ? strerror(errno) : "");
		failures++;
	}
}

#define CHECK_RECEIVED(fd, expected) check_received(fd, expected, __LINE__)

static int receiver_fd = -1;
static volatile sig_atomic_t ticks = 0;

/* Run on top of the stack the interrupted syscall was using, then
 * empty the queue of the receiver after a few runs, so the blocked
 * sender can proceed.  */
static void handler(int signo)
{
	volatile char frame[4096];
	char buffer[16];

	(void) signo;
	frame[0] = frame[sizeof(frame) - 1] = 1;

	if (++ticks == 5) {
		while (recv(receiver_fd, buffer, sizeof(buffer), MSG_DONTWAIT) >= 0)
			;
	}
}

/* Fill the queue of the receiver, so the next send blocks.  */
static int fill_queue(const struct sockaddr_un *receiver, int sender)
{
	int i;

	for (i = 0; i < 64; i++) {
		int fd = new_socket(NULL);

		if (connect(fd, (const struct sockaddr *) receiver, sizeof(*receiver)) < 0)
			return -1;

		while (send(fd, "f", 1, MSG_DONTWAIT) > 0)
			;

		if (sendto(sender, "p", 1, MSG_DONTWAIT, (const struct sockaddr *) receiver,
			   sizeof(*receiver)) < 0 && errno == EAGAIN)
			return 0;
	}

	return -1;
}

/* Send a datagram with @method while the queue of the receiver is
 * full, and have a signal handler interrupt it.  */
static void check_restart(const struct sockaddr_un *receiver, int sender, int method)
{
	struct itimerval timer = { { 0, 50000 }, { 0, 50000 } };
	struct iovec iov = { "restarted", 9 };
	struct mmsghdr mmsghdr;
	struct sigaction action;
	struct msghdr msghdr;
	ssize_t status;

	if (fill_queue(receiver, sender) < 0) {
		fprintf(stderr, "can't fill the queue of the receiver, skipped\n");
		return;
	}

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name    = (void *) receiver;
	msghdr.msg_namelen = sizeof(*receiver);
	msghdr.msg_iov     = &iov;
	msghdr.msg_iovlen  = 1;

	memset(&mmsghdr, 0, sizeof(mmsghdr));
	mmsghdr.msg_hdr = msghdr;

	memset(&action, 0, sizeof(action));
	action.sa_handler = handler;
	action.sa_flags   = SA_RESTART;
	(void) sigaction(SIGALRM, &action, NULL);

	ticks = 0;
	(void) setitimer(ITIMER_REAL, &timer, NULL);

	errno = 0;
	switch (method) {
	case 0:
		status = sendto(sender, "restarted", 9, 0, (const struct sockaddr *) receiver,
				sizeof(*receiver));
		CHECK(status == 9);
		break;

	case 1:
		status = sendmsg(sender, &msghdr, 0);
		CHECK(status == 9);
		break;

	default:
		status = sendmmsg(sender, &mmsghdr, 1, 0);
		CHECK(status == 1 && mmsghdr.msg_len == 9);
		break;
	}

	memset(&timer, 0, sizeof(timer));
	(void) setitimer(ITIMER_REAL, &timer, NULL);

	CHECK(ticks >= 5);
	CHECK_RECEIVED(receiver_fd, "restarted");
}

int main(void)
{
	struct sockaddr_un receiver, sender, missing, relative, from;
	struct mmsghdr mmsghdrs[3];
	struct iovec iovs[3] = { { "aa", 2 }, { "bbbb", 4 }, { "cccccc", 6 } };
	struct msghdr msghdr;
	socklen_t length;
	char buffer[16];
	int named, unnamed;
	int i;

	(void) mkdir("/tmp", 0777);
	(void) mkdir(DIR, 0700);

	receiver_fd = new_socket(RECEIVER);
	named       = new_socket(SENDER);
	unnamed     = new_socket(NULL);

	make_address(&receiver, RECEIVER);
	make_address(&sender, SENDER);
	make_address(&missing, MISSING);
	make_address(&relative, "r");

	/* sendto(2) to an absolute path.  */
	CHECK(sendto(unnamed, "to", 2, 0, (struct sockaddr *) &receiver, sizeof(receiver)) == 2);
	CHECK_RECEIVED(receiver_fd, "to");

	/* sendto(2) with the exact length of the address.  */
	CHECK(sendto(unnamed, "exact", 5, 0, (struct sockaddr *) &receiver,
		     offsetof(struct sockaddr_un, sun_path) + strlen(RECEIVER) + 1) == 5);
	CHECK_RECEIVED(receiver_fd, "exact");

	/* sendmsg(2): its struct msghdr is left as is.  */
	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name    = &receiver;
	msghdr.msg_namelen = sizeof(receiver);
	msghdr.msg_iov     = &iovs[0];
	msghdr.msg_iovlen  = 1;
	CHECK(sendmsg(unnamed, &msghdr, 0) == 2);
	CHECK(msghdr.msg_name == &receiver && msghdr.msg_namelen == sizeof(receiver));
	CHECK(strcmp(receiver.sun_path, RECEIVER) == 0);
	CHECK_RECEIVED(receiver_fd, "aa");

	/* sendmmsg(2): the length sent of each message is reported in
	 * the caller's vector, its names are left as is.  */
	memset(mmsghdrs, 0, sizeof(mmsghdrs));
	for (i = 0; i < 3; i++) {
		mmsghdrs[i].msg_hdr.msg_name    = &receiver;
		mmsghdrs[i].msg_hdr.msg_namelen = sizeof(receiver);
		mmsghdrs[i].msg_hdr.msg_iov     = &iovs[i];
		mmsghdrs[i].msg_hdr.msg_iovlen  = 1;
		mmsghdrs[i].msg_len = 12345;
	}
	CHECK(sendmmsg(unnamed, mmsghdrs, 3, 0) == 3);
	CHECK(mmsghdrs[0].msg_len == 2 && mmsghdrs[1].msg_len == 4 && mmsghdrs[2].msg_len == 6);
	CHECK(mmsghdrs[1].msg_hdr.msg_name == &receiver
	      && mmsghdrs[1].msg_hdr.msg_namelen == sizeof(receiver));
	CHECK_RECEIVED(receiver_fd, "aa");
	CHECK_RECEIVED(receiver_fd, "bbbb");
	CHECK_RECEIVED(receiver_fd, "cccccc");

	/* sendmmsg(2) stops at the first message it can't send.  */
	mmsghdrs[1].msg_hdr.msg_name = &missing;
	for (i = 0; i < 3; i++)
		mmsghdrs[i].msg_len = 12345;
	CHECK(sendmmsg(unnamed, mmsghdrs, 3, 0) == 1);
	CHECK(mmsghdrs[0].msg_len == 2 && mmsghdrs[1].msg_len == 12345);
	CHECK_RECEIVED(receiver_fd, "aa");

	mmsghdrs[0].msg_hdr.msg_name = &missing;
	errno = 0;
	CHECK(sendmmsg(unnamed, mmsghdrs, 3, 0) < 0 && errno == ENOENT);

	/* A relative path is resolved against the working directory.  */
	CHECK(chdir(DIR) == 0);
	CHECK(sendto(unnamed, "relative", 8, 0, (struct sockaddr *) &relative, sizeof(relative)) == 8);
	CHECK_RECEIVED(receiver_fd, "relative");
	CHECK(chdir("/") == 0);

	/* A reply to the sender address recvfrom(2) reports.  */
	CHECK(sendto(named, "ping", 4, 0, (struct sockaddr *) &receiver, sizeof(receiver)) == 4);
	memset(&from, 0, sizeof(from));
	length = sizeof(from);
	CHECK(recvfrom(receiver_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &from, &length) == 4);
	CHECK(sendto(receiver_fd, "pong", 4, 0, (struct sockaddr *) &from, length) == 4);
	CHECK_RECEIVED(named, "pong");

	/* Same with recvmsg(2) and sendmsg(2).  */
	CHECK(sendto(named, "ping", 4, 0, (struct sockaddr *) &receiver, sizeof(receiver)) == 4);
	memset(&from, 0, sizeof(from));
	memset(&msghdr, 0, sizeof(msghdr));
	iovs[0].iov_base   = buffer;
	iovs[0].iov_len    = sizeof(buffer);
	msghdr.msg_name    = &from;
	msghdr.msg_namelen = sizeof(from);
	msghdr.msg_iov     = &iovs[0];
	msghdr.msg_iovlen  = 1;
	CHECK(recvmsg(receiver_fd, &msghdr, 0) == 4);
	iovs[0].iov_base = "pong";
	iovs[0].iov_len  = 4;
	CHECK(sendmsg(receiver_fd, &msghdr, 0) == 4);
	CHECK_RECEIVED(named, "pong");

	/* A blocking send interrupted by a signal handler.  */
	for (i = 0; i < 3; i++)
		check_restart(&receiver, unnamed, i);

	(void) unlink(RECEIVER);
	(void) unlink(SENDER);
	(void) rmdir(DIR);

	return (failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
