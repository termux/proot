/* Print the credentials getsockopt(SO_PEERCRED) reports for the peer
 * of a socket pair, then send a message on it, plain and along with
 * the credentials the process has to its own eyes, which the kernel
 * accepts only if they are its actual ones.  32-bit x86 programs make
 * these syscalls through socketcall(2).  */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>

int main(void)
{
	char control[CMSG_SPACE(sizeof(struct ucred))];
	char buffer[8] = "hello";
	struct iovec iov = { buffer, 5 };
	struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };
	socklen_t length = sizeof(struct ucred);
	struct cmsghdr *cmsg;
	struct ucred cred;
	int sockets[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		perror("socketpair");
		return 1;
	}

	if (getsockopt(sockets[0], SOL_SOCKET, SO_PEERCRED, &cred, &length) < 0) {
		perror("getsockopt");
		return 1;
	}
	printf("peer uid=%u gid=%u\n", (unsigned) cred.uid, (unsigned) cred.gid);

	if (sendmsg(sockets[0], &message, 0) != 5
	    || read(sockets[1], buffer, sizeof(buffer)) != 5) {
		perror("sendmsg");
		return 1;
	}

	cred.pid = getpid();
	cred.uid = geteuid();
	cred.gid = getegid();

	memset(control, 0, sizeof(control));
	message.msg_control = control;
	message.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(cred));
	memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

	if (sendmsg(sockets[0], &message, 0) != 5) {
		perror("sendmsg(SCM_CREDENTIALS)");
		return 1;
	}

	printf("sent\n");
	return 0;
}
