#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Open argv[1] without following it -- O_NOFOLLOW, along with O_PATH
 * when argv[2] is "path" -- then print the name "/proc/self/fd/<FD>"
 * reports for this descriptor.  */
int main(int argc, char *argv[])
{
	char link[64];
	char path[PATH_MAX];
	ssize_t status;
	int flags;
	int fd;

	if (argc < 2)
		exit(EXIT_FAILURE);

	flags = O_RDONLY | O_NOFOLLOW;
	if (argc > 2 && strcmp(argv[2], "path") == 0)
		flags = O_PATH | O_NOFOLLOW;

	fd = open(argv[1], flags);
	if (fd < 0)
		exit(EXIT_FAILURE);

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);

	status = readlink(link, path, PATH_MAX - 1);
	if (status < 0 || status >= PATH_MAX)
		exit(EXIT_FAILURE);
	path[status] = '\0';

	puts(path);
	exit(EXIT_SUCCESS);
}
