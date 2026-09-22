#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
#ifdef SYS_execveat
	if (argc < 2)
		return EXIT_FAILURE;

	syscall(SYS_execveat, AT_FDCWD, argv[1], &argv[1], environ, 0);
	return errno == ENOSYS ? 125 : EXIT_FAILURE;
#else
	(void) argc;
	(void) argv;
	return 125;
#endif
}
