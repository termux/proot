#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

/* Call fchmodat2(2) directly, as C libraries can't be relied on to: glibc
 * only uses it for AT_SYMLINK_NOFOLLOW, musl never does.
 *
 *     fchmodat2 [-n] [-d DIR] PATH MODE EXPECT
 *
 * MODE is octal.  With -n the flags are AT_SYMLINK_NOFOLLOW.  With -d PATH
 * is relative to the directory DIR instead of the current one.  EXPECT is
 * "ok" or the name of the expected error.  Exit with 0 if that's what the
 * syscall did, with 125 if the kernel doesn't know the syscall (so the
 * test is skipped) and with 1 otherwise.  */
int main(int argc, char *argv[])
{
	static const struct {
		const char *name;
		int error;
	} expectations[] = {
		{ "ok",		0 },
		{ "ENOENT",	ENOENT },
		{ "EOPNOTSUPP",	EOPNOTSUPP },
	};
	const char *dir = NULL;
	int dirfd = AT_FDCWD;
	int flags = 0;
	int expected = -1;
	int status;
	int opt;
	int i;

	while ((opt = getopt(argc, argv, "nd:")) != -1) {
		switch (opt) {
		case 'n':
			flags = AT_SYMLINK_NOFOLLOW;
			break;
		case 'd':
			dir = optarg;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (argc - optind != 3)
		exit(EXIT_FAILURE);

	for (i = 0; i < sizeof(expectations) / sizeof(expectations[0]); i++) {
		if (strcmp(argv[optind + 2], expectations[i].name) == 0)
			expected = expectations[i].error;
	}
	if (expected < 0)
		exit(EXIT_FAILURE);

	if (dir != NULL) {
		dirfd = open(dir, O_RDONLY | O_DIRECTORY);
		if (dirfd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
	}

	status = syscall(SYS_fchmodat2, dirfd, argv[optind],
			(mode_t) strtoul(argv[optind + 1], NULL, 8), flags);
	if (status < 0 && errno == ENOSYS)
		exit(125);

	if ((status < 0 ? errno : 0) != expected) {
		fprintf(stderr, "fchmodat2: expected %s, got %s\n",
			argv[optind + 2], status < 0 ? strerror(errno) : "ok");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
