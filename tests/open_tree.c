#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* The numbers are the same on every architecture, and C libraries have no
 * wrappers for these syscalls anyway.  */
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_fsopen
#define SYS_fsopen 430
#endif
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif
#ifndef SYS_fsmount
#define SYS_fsmount 432
#endif
#ifndef SYS_fspick
#define SYS_fspick 433
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef SYS_open_tree_attr
#define SYS_open_tree_attr 467
#endif

#define OPEN_TREE_CLONE		1
#define AT_RECURSIVE_		0x8000

/* Call the open_tree(2) family of syscalls directly.
 *
 *     open_tree [-c] [-e] [-n] [-r] [-d DIR] [-s SAME] PATH EXPECT
 *     open_tree -m CALL
 *
 * The first form calls open_tree(2).  With -c the flags include
 * OPEN_TREE_CLONE, with -e AT_EMPTY_PATH, with -n AT_SYMLINK_NOFOLLOW and
 * with -r AT_RECURSIVE.  With -d PATH is relative to the directory DIR
 * instead of the current one.  With -s the returned descriptor must refer
 * to the same file as the one SAME names (a symlink itself with -n); it is
 * checked with stat(2), thus in the same way as PATH is looked up.  EXPECT
 * is "ok" or the name of the expected error.  Exit with 0 if that's what
 * the syscall did, with 125 if it failed with ENOSYS although another
 * outcome was expected (the kernel or the seccomp policy doesn't have the
 * syscall, so the test is skipped) and with 1 otherwise.
 *
 * The second form calls CALL, one of the other syscalls of the file
 * descriptor based mount API, with harmless arguments and exits with 0 if
 * it failed with ENOSYS.  */
static const struct {
	const char *name;
	int error;
} expectations[] = {
	{ "ok",		0 },
	{ "ENOENT",	ENOENT },
	{ "EINVAL",	EINVAL },
	{ "ENOSYS",	ENOSYS },
};

static long other_call(const char *name)
{
	if (strcmp(name, "fsopen") == 0)
		return syscall(SYS_fsopen, "tmpfs", 1 /* FSOPEN_CLOEXEC */);
	if (strcmp(name, "fsconfig") == 0)
		return syscall(SYS_fsconfig, -1, 0 /* FSCONFIG_SET_FLAG */, "ro", NULL, 0);
	if (strcmp(name, "fsmount") == 0)
		return syscall(SYS_fsmount, -1, 1 /* FSMOUNT_CLOEXEC */, 0);
	if (strcmp(name, "fspick") == 0)
		return syscall(SYS_fspick, AT_FDCWD, "/", 1 /* FSPICK_CLOEXEC */);
	if (strcmp(name, "move_mount") == 0)
		return syscall(SYS_move_mount, -1, "", -1, "",
			       0x4 /* MOVE_MOUNT_F_EMPTY_PATH */ | 0x40 /* MOVE_MOUNT_T_EMPTY_PATH */);
	if (strcmp(name, "mount_setattr") == 0)
		return syscall(SYS_mount_setattr, -1, "", AT_EMPTY_PATH, NULL, 0);
	if (strcmp(name, "open_tree_attr") == 0)
		return syscall(SYS_open_tree_attr, AT_FDCWD, "/", 0, NULL, 0);

	errno = EINVAL;
	return -2;
}

int main(int argc, char *argv[])
{
	const char *dir = NULL;
	const char *same = NULL;
	int dirfd = AT_FDCWD;
	unsigned int flags = 0;
	int expected = -1;
	struct stat expected_stat;
	struct stat actual_stat;
	long status;
	int opt;
	int i;

	while ((opt = getopt(argc, argv, "cenrd:s:m:")) != -1) {
		switch (opt) {
		case 'c':
			flags |= OPEN_TREE_CLONE;
			break;
		case 'e':
			flags |= AT_EMPTY_PATH;
			break;
		case 'n':
			flags |= AT_SYMLINK_NOFOLLOW;
			break;
		case 'r':
			flags |= AT_RECURSIVE_;
			break;
		case 'd':
			dir = optarg;
			break;
		case 's':
			same = optarg;
			break;
		case 'm':
			status = other_call(optarg);
			if (status == -2)
				exit(EXIT_FAILURE);
			if (status >= 0 || errno != ENOSYS) {
				fprintf(stderr, "%s: expected ENOSYS, got %s\n", optarg,
					status < 0 ? strerror(errno) : "ok");
				exit(EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (argc - optind != 2)
		exit(EXIT_FAILURE);

	for (i = 0; i < sizeof(expectations) / sizeof(expectations[0]); i++) {
		if (strcmp(argv[optind + 1], expectations[i].name) == 0)
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

	status = syscall(SYS_open_tree, dirfd, argv[optind], flags);
	if (status < 0 && errno == ENOSYS && expected != ENOSYS)
		exit(125);

	if ((status < 0 ? errno : 0) != expected) {
		fprintf(stderr, "open_tree: expected %s, got %s\n",
			argv[optind + 1], status < 0 ? strerror(errno) : "ok");
		exit(EXIT_FAILURE);
	}

	if (status >= 0 && same != NULL) {
		if (fstat(status, &actual_stat) < 0
		    || ((flags & AT_SYMLINK_NOFOLLOW) != 0
			? lstat(same, &expected_stat) : stat(same, &expected_stat)) < 0) {
			perror("stat");
			exit(EXIT_FAILURE);
		}

		if (actual_stat.st_dev != expected_stat.st_dev
		    || actual_stat.st_ino != expected_stat.st_ino) {
			fprintf(stderr, "open_tree: %s is not the same file as %s\n",
				argv[optind], same);
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
}
