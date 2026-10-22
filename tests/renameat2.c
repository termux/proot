#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* renameat2 OLD NEW FLAGS: rename OLD to NEW the way the kernel is
 * asked to, mv(1) refuses for instance when both are the same file.  */
int main(int argc, char **argv)
{
#ifdef SYS_renameat2
	if (argc < 4)
		return EXIT_FAILURE;

	if (syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], atoi(argv[3])) == 0)
		return EXIT_SUCCESS;
	return errno == ENOSYS ? 125 : EXIT_FAILURE;
#else
	(void) argc;
	(void) argv;
	return 125;
#endif
}
