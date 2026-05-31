/* Regression test for openat2(2) support under PRoot.
 *
 * openat2() is used by modern tar/coreutils (e.g. to safely create
 * symlinks during extraction with RESOLVE_BENEATH).  PRoot must
 * translate it like openat(); otherwise paths are left untranslated
 * (escaping the guest rootfs) or, when an outer seccomp policy rejects
 * the newer syscall, it fails with ENOSYS ("Function not implemented").
 *
 * Exit codes: 0 = ok, 125 = skipped (openat2 unavailable), else = fail. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08
#endif

struct test_open_how {
	unsigned long long flags;
	unsigned long long mode;
	unsigned long long resolve;
};

static int sys_openat2(int dirfd, const char *path, unsigned long long flags,
		       unsigned long long mode, unsigned long long resolve)
{
	struct test_open_how how = { .flags = flags, .mode = mode, .resolve = resolve };
	return syscall(__NR_openat2, dirfd, path, &how, sizeof(how));
}

#define MARKER  "/tmp/openat2_marker"
#define PAYLOAD "openat2-payload"

int main(void)
{
	int fd, n;
	char buf[64] = { 0 };

	/* Create the marker with a regular open(): PRoot always translates
	 * this, so it reliably lands inside the guest rootfs.  */
	fd = open(MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open(O_CREAT)");
		exit(EXIT_FAILURE);
	}
	if (write(fd, PAYLOAD, strlen(PAYLOAD)) != (ssize_t) strlen(PAYLOAD)) {
		perror("write");
		exit(EXIT_FAILURE);
	}
	close(fd);

	/* Open the same absolute path with openat2().  If PRoot does not
	 * translate openat2(), this resolves against the host root instead
	 * of the rootfs and fails (or reads a different file).  */
	fd = sys_openat2(AT_FDCWD, MARKER, O_RDONLY, 0, 0);
	if (fd < 0) {
		if (errno == ENOSYS) {
			/* openat2 genuinely unavailable: skip.  */
			exit(125);
		}
		fprintf(stderr, "openat2(%s) absolute: %s\n", MARKER, strerror(errno));
		exit(EXIT_FAILURE);
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0 || strcmp(buf, PAYLOAD) != 0) {
		fprintf(stderr, "openat2 read mismatch: '%s' (path not confined to rootfs?)\n", buf);
		exit(EXIT_FAILURE);
	}

	/* tar's symlink-extraction pattern: open the parent directory with
	 * openat2(RESOLVE_BENEATH | O_PATH | O_DIRECTORY | O_NOFOLLOW), then
	 * symlinkat() into it.  */
	fd = sys_openat2(AT_FDCWD, "/tmp",
			 O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_PATH | O_DIRECTORY,
			 0, RESOLVE_BENEATH);
	if (fd < 0) {
		fprintf(stderr, "openat2(/tmp, RESOLVE_BENEATH): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	unlinkat(fd, "openat2_link", 0);
	if (symlinkat("openat2_marker", fd, "openat2_link") < 0) {
		fprintf(stderr, "symlinkat under openat2 dirfd: %s\n", strerror(errno));
		close(fd);
		exit(EXIT_FAILURE);
	}
	close(fd);

	if (readlink("/tmp/openat2_link", buf, sizeof(buf) - 1) < 0) {
		perror("readlink");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
