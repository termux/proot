/* Preloaded into PRoot by test-738b8dfc.sh, makes the host look like
 * an Android app sandbox: rtnetlink requests that would reconfigure the
 * network are refused in sendto(2) with EACCES, queries go through.
 * That is what makes PRoot substitute an AF_UNIX socket for each
 * NETLINK_ROUTE socket of the tracees (see host_blocks_af_netlink()).
 * Only PRoot itself is affected, not the programs it runs -- nor
 * Valgrind's own processes, apart from the PRoot it checks.  */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int in_proot;

__attribute__((constructor)) static void init(void)
{
	char comm[32] = "";
	int fd = open("/proc/self/comm", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, comm, sizeof(comm) - 1) < 0)
			comm[0] = '\0';
		close(fd);
	}
	in_proot = (strncmp(comm, "proot", 5) == 0 || strncmp(comm, "memcheck", 8) == 0);
}

static int denied(int fd, const void *buf, size_t len)
{
	const struct nlmsghdr *header = buf;
	socklen_t size = sizeof(int);
	int domain = 0;

	if (!in_proot || len < sizeof(*header))
		return 0;

	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size) < 0 || domain != AF_NETLINK)
		return 0;

	/* rtnetlink types come as NEW, DEL, GET, SET.  */
	if (header->nlmsg_type < RTM_BASE || header->nlmsg_type > RTM_MAX)
		return 0;
	return ((header->nlmsg_type - RTM_BASE) & 3) != 2;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
	       const struct sockaddr *address, socklen_t address_len)
{
	static ssize_t (*next)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

	if (next == NULL)
		next = dlsym(RTLD_NEXT, "sendto");

	if (denied(fd, buf, len)) {
		errno = EACCES;
		return -1;
	}

	return next(fd, buf, len, flags, address, address_len);
}
