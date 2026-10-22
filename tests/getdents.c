#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* List PATH with getdents64(2) -- and with getdents(2) where the ABI
 * has it -- both with a large buffer and with a buffer that holds a
 * single entry, then print "<syscall> <name> <d_type> <type from lstat>"
 * for each entry but "." and "..", or "<syscall> error <errno>" when a
 * listing fails.  PATH is opened as is, so that a file that is not a
 * directory makes getdents(2) itself fail.  This program exits with 1
 * if any d_type is not the type lstat(2) reports, or if a listing
 * fails.  */

struct dirent64_raw {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

#ifdef SYS_getdents
struct dirent_raw {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
};
#endif

static int check(int dir_fd, const char *syscall_name, const char *name, unsigned char type)
{
	struct stat statl;
	int lstat_type;

	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return 0;

	lstat_type = (fstatat(dir_fd, name, &statl, AT_SYMLINK_NOFOLLOW) < 0)
		? -1 : (int) IFTODT(statl.st_mode);

	printf("%s %s %d %d\n", syscall_name, name, type, lstat_type);

	return type != lstat_type;
}

static int list(const char *path, int use_getdents64, size_t size)
{
	const char *syscall_name = use_getdents64 ? "getdents64" : "getdents";
	char *buffer;
	long result;
	long offset;
	int status = 0;
	int fd;

	buffer = malloc(size);
	fd = open(path, O_RDONLY);
	if (buffer == NULL || fd < 0) {
		perror(path);
		return 1;
	}

	while (1) {
#ifdef SYS_getdents
		if (!use_getdents64)
			result = syscall(SYS_getdents, fd, buffer, size);
		else
#endif
			result = syscall(SYS_getdents64, fd, buffer, size);
		if (result < 0) {
			printf("%s error %d\n", syscall_name, errno);
			status = 1;
			break;
		}
		if (result == 0)
			break;

		for (offset = 0; offset < result; ) {
			if (use_getdents64) {
				struct dirent64_raw *entry = (void *) (buffer + offset);
				status |= check(fd, syscall_name, entry->d_name, entry->d_type);
				offset += entry->d_reclen;
			}
#ifdef SYS_getdents
			else {
				struct dirent_raw *entry = (void *) (buffer + offset);
				status |= check(fd, syscall_name, entry->d_name,
						buffer[offset + entry->d_reclen - 1]);
				offset += entry->d_reclen;
			}
#endif
		}
	}

	close(fd);
	free(buffer);

	return status;
}

int main(int argc, char *argv[])
{
	/* Large enough for a single entry whose name has up to 64
	 * characters, whatever the structure.  */
	const size_t small = 96;
	int status = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PATH\n", argv[0]);
		return 2;
	}

	status |= list(argv[1], 1, 32768);
	status |= list(argv[1], 1, small);
#ifdef SYS_getdents
	status |= list(argv[1], 0, 32768);
	status |= list(argv[1], 0, small);
#endif

	return status;
}
