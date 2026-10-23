#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/stat.h>

/* Call statx(2) directly, as C libraries pick their own stat syscall:
 * glibc 2.33+ uses statx for stat(3) on 32-bit ABIs, fstatat on 64-bit
 * ones, and coreutils calls statx itself.
 *
 *     statx [-n] PATH
 *
 * Print the permission bits of PATH in octal, or the name of the error.
 * With -n the flags are AT_SYMLINK_NOFOLLOW.  Exit with 0 if the syscall
 * succeeded, with 125 if the kernel doesn't know it (so the test is
 * skipped) and with 1 otherwise.  */
int main(int argc, char *argv[])
{
	struct statx statx_buf;
	int flags = 0;
	int status;
	int opt;

	while ((opt = getopt(argc, argv, "n")) != -1) {
		switch (opt) {
		case 'n':
			flags = AT_SYMLINK_NOFOLLOW;
			break;
		default:
			return 1;
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, "usage: statx [-n] PATH\n");
		return 1;
	}

	memset(&statx_buf, 0, sizeof(statx_buf));
	status = syscall(SYS_statx, AT_FDCWD, argv[optind], flags, STATX_MODE, &statx_buf);
	if (status < 0) {
		switch (errno) {
		case ENOSYS:
			return 125;
		case EACCES:
			puts("EACCES");
			break;
		case ENOENT:
			puts("ENOENT");
			break;
		default:
			printf("errno %d\n", errno);
			break;
		}
		return 1;
	}

	if ((statx_buf.stx_mask & STATX_MODE) == 0) {
		puts("no STATX_MODE");
		return 1;
	}

	printf("%o\n", statx_buf.stx_mode & 07777);
	return 0;
}
