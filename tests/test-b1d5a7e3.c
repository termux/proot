/* PRoot emulates a bind mount with a binding, that is a path to the
 * file the guest mounted, whereas a mount holds that file: once the
 * guest removed it, the mount point led nowhere.  bubblewrap does so
 * for --bind-data and --ro-bind-data, it removes the source of the
 * mount right after, so the file was missing in the sandbox.  */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SIZE (PATH_MAX / 2)

static char base[SIZE];
static char temp_directory[PATH_MAX];
static char prefix[64];
static bool proot;
static int failed;

#define CHECK(condition) do {						\
	if (!(condition)) {						\
		fprintf(stderr, "line %d: %s failed (%s)\n", __LINE__,	\
			#condition, strerror(errno));			\
		failed = 1;						\
	}								\
} while (0)

/* Path @name below the base directory.  */
static const char *at(const char *name)
{
	static char path[4][PATH_MAX];
	static int i;

	i = (i + 1) % 4;
	snprintf(path[i], sizeof(path[i]), "%s/%s", base, name);
	return path[i];
}

/* Number of entries starting with @start in @path, or -1 on error.  */
static int count(const char *path, const char *start)
{
	struct dirent *entry;
	int result = 0;
	DIR *dir;

	dir = opendir(path);
	if (dir == NULL)
		return -1;
	while ((entry = readdir(dir)) != NULL)
		if (   strcmp(entry->d_name, ".") != 0
		    && strcmp(entry->d_name, "..") != 0
		    && strncmp(entry->d_name, start, strlen(start)) == 0)
			result++;
	closedir(dir);
	return result;
}

/* Whether the parent of this first tracee is PRoot.  */
static bool parent_is_proot(void)
{
	char path[64];
	char comm[16] = "";
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/comm", getppid());
	file = fopen(path, "r");
	if (file == NULL)
		return false;
	if (fgets(comm, sizeof(comm), file) == NULL)
		comm[0] = '\0';
	fclose(file);
	return strncmp(comm, "proot", strlen("proot")) == 0;
}

/* Whether PRoot keeps @expected removed files for the bindings to
 * them.  Natively, the mounts hold them.  */
static bool kept(int expected)
{
	return !proot || count(temp_directory, prefix) == expected;
}

static int write_file(const char *path, const char *content)
{
	size_t length = strlen(content);
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (write(fd, content, length) != (ssize_t) length) {
		close(fd);
		return -1;
	}
	return close(fd);
}

static int read_file(const char *path, const char *content)
{
	size_t length = strlen(content);
	char buffer[16];
	ssize_t size;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	size = read(fd, buffer, sizeof(buffer));
	close(fd);
	return size == (ssize_t) length && memcmp(buffer, content, length) == 0 ? 0 : -1;
}

static void post(int fd)
{
	CHECK(write(fd, "", 1) == 1);
}

static void fetch(int fd)
{
	char byte;

	CHECK(read(fd, &byte, 1) == 1);
}

static void wait_child(pid_t pid)
{
	int status = -1;

	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* The source "t/src", in a tmpfs as with bubblewrap, is bound to "dst".  */
static void mount_source(void)
{
	CHECK(mount("tmpfs", at("t"), "tmpfs", 0, NULL) == 0);
	CHECK(write_file(at("t/src"), "data") == 0);
	CHECK(write_file(at("dst"), "") == 0);
	CHECK(mount(at("t/src"), at("dst"), NULL, MS_BIND, NULL) == 0);
}

static void unmount_source(void)
{
	CHECK(umount(at("dst")) == 0);
	CHECK(umount(at("t")) == 0);
	CHECK(unlink(at("dst")) == 0);
}

/* The mount point still leads to the file once its source is removed,
 * through its path or @by_descriptor, until it's unmounted.  */
static void removed(bool by_descriptor)
{
	struct stat statl;
	int dirfd;

	mount_source();

	if (by_descriptor) {
		dirfd = open(at("t"), O_RDONLY | O_DIRECTORY);
		CHECK(dirfd >= 0);
		CHECK(unlinkat(dirfd, "src", 0) == 0);
		close(dirfd);
	}
	else
		CHECK(unlink(at("t/src")) == 0);

	errno = 0;
	CHECK(access(at("t/src"), F_OK) < 0 && errno == ENOENT);
	CHECK(count(at("t"), "") == 0);
	CHECK(read_file(at("dst"), "data") == 0);
	CHECK(kept(1));

	/* A bind mount of a file is read-write.  */
	CHECK(write_file(at("dst"), "other") == 0);
	CHECK(read_file(at("dst"), "other") == 0);

	/* The mount point is the empty file again.  */
	CHECK(umount(at("dst")) == 0);
	CHECK(stat(at("dst"), &statl) == 0 && statl.st_size == 0);
	CHECK(kept(0));

	CHECK(umount(at("t")) == 0);
	CHECK(unlink(at("dst")) == 0);
}

/* unlinkat(AT_REMOVEDIR) doesn't remove a file.  */
static void not_a_directory(void)
{
	mount_source();

	errno = 0;
	CHECK(unlinkat(AT_FDCWD, at("t/src"), AT_REMOVEDIR) < 0 && errno == ENOTDIR);
	CHECK(access(at("t/src"), F_OK) == 0);
	CHECK(read_file(at("dst"), "data") == 0);
	CHECK(kept(0));

	CHECK(unlink(at("t/src")) == 0);
	unmount_source();
	CHECK(kept(0));
}

/* A mount name-space made after the mount keeps it, whichever tracee
 * removes the source.  */
static void other_name_space(void)
{
	int to_parent[2];
	int to_child[2];
	pid_t pid;

	mount_source();

	CHECK(pipe(to_parent) == 0 && pipe(to_child) == 0);
	pid = fork();
	if (pid == 0) {
		failed = 0;
		CHECK(unshare(CLONE_NEWNS) == 0);
		post(to_parent[1]);
		fetch(to_child[0]);
		CHECK(read_file(at("dst"), "data") == 0);
		_exit(failed);
	}

	fetch(to_parent[0]);
	CHECK(unlink(at("t/src")) == 0);
	CHECK(read_file(at("dst"), "data") == 0);
	post(to_child[1]);
	wait_child(pid);

	CHECK(kept(1));
	CHECK(umount(at("dst")) == 0);
	CHECK(kept(0));
	CHECK(umount(at("t")) == 0);
	CHECK(unlink(at("dst")) == 0);

	close(to_parent[0]);
	close(to_parent[1]);
	close(to_child[0]);
	close(to_child[1]);
}

/* The file is removed along with the last binding to it, here with the
 * mount name-space of a tracee that exits.  */
static void mounter_exits(void)
{
	pid_t pid;

	CHECK(write_file(at("dst"), "") == 0);

	pid = fork();
	if (pid == 0) {
		failed = 0;
		CHECK(unshare(CLONE_NEWNS) == 0);
		CHECK(mount("tmpfs", at("t"), "tmpfs", 0, NULL) == 0);
		CHECK(write_file(at("t/src"), "data") == 0);
		CHECK(mount(at("t/src"), at("dst"), NULL, MS_BIND, NULL) == 0);
		CHECK(unlink(at("t/src")) == 0);
		CHECK(read_file(at("dst"), "data") == 0);
		CHECK(kept(1));
		_exit(failed);
	}
	wait_child(pid);

	CHECK(kept(0));
	CHECK(read_file(at("dst"), "") == 0);
	CHECK(unlink(at("dst")) == 0);
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	const char *proot_tmpdir = getenv("PROOT_TMP_DIR");

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (   (unshare(0) < 0 && errno == EPERM)
	    || (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM))
		exit(125);

	/* Where PRoot keeps the removed files, see create_temp_name().  */
	if (realpath(proot_tmpdir ? proot_tmpdir : P_tmpdir, temp_directory) == NULL) {
		perror("realpath");
		exit(EXIT_FAILURE);
	}
	snprintf(prefix, sizeof(prefix), "proot-unlinked-%d-", getppid());
	proot = parent_is_proot();

	snprintf(base, sizeof(base), "%s/test-b1d5a7e3-XXXXXX", tmpdir ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	if (mkdir(at("t"), 0700) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	removed(false);
	removed(true);
	not_a_directory();
	other_name_space();
	mounter_exits();

	CHECK(rmdir(at("t")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
