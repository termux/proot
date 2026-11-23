#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Open the directory PATH1 with O_PATH and close it, then open the
 * directory PATH2, which gets the same descriptor number, and print the
 * content of the file RELATIVE below this latter descriptor.
 *
 *     fd_reuse PATH1 PATH2 RELATIVE
 *
 * Exit with 125 if the descriptor number isn't reused (so the test is
 * skipped) and with 1 if anything fails.  */

int main(int argc, char *argv[])
{
	char buffer[64];
	ssize_t size;
	int fd1;
	int fd2;
	int fd3;

	if (argc != 4) {
		fprintf(stderr, "usage: fd_reuse PATH1 PATH2 RELATIVE\n");
		return 1;
	}

	fd1 = open(argv[1], O_PATH | O_DIRECTORY);
	if (fd1 < 0) {
		perror("open PATH1");
		return 1;
	}
	close(fd1);

	fd2 = open(argv[2], O_RDONLY | O_DIRECTORY);
	if (fd2 < 0) {
		perror("open PATH2");
		return 1;
	}
	if (fd2 != fd1) {
		fprintf(stderr, "descriptor %d not reused (%d)\n", fd1, fd2);
		return 125;
	}

	fd3 = openat(fd2, argv[3], O_RDONLY);
	if (fd3 < 0) {
		perror("openat RELATIVE");
		return 1;
	}

	size = read(fd3, buffer, sizeof(buffer));
	if (size < 0) {
		perror("read");
		return 1;
	}

	if (write(1, buffer, size) != size)
		return 1;

	return 0;
}
