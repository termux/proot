/* PRoot emulates the mount(2) of a tmpfs by binding a new temporary
 * directory.  This directory was removed along with the file-system
 * name-space of the tracee that mounted it, rather than once no binding
 * led to it anymore:
 *
 * - the mount point led to a removed directory as soon as that tracee
 *   was gone, as mount(8) is right after mounting, whichever tracee
 *   still used it, in the same mount name-space or in another one;
 *
 * - chroot(2) into the tmpfs (with -0) removed it at once;
 *
 * - otherwise, it stayed with its files after umount(2), or a mount(2)
 *   over it, as long as that tracee was alive.  */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define SIZE (PATH_MAX / 2)

static char base[SIZE];
static char temp_directory[PATH_MAX];
static char prefix[64];
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

/* Number of the directories of the tmpfs PRoot, the parent of this
 * first tracee, still keeps, or -1 on error.  */
static int tmpfs_count(void)
{
	struct dirent *entry;
	int count = 0;
	DIR *dir;

	dir = opendir(temp_directory);
	if (dir == NULL)
		return -1;
	while ((entry = readdir(dir)) != NULL)
		if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0)
			count++;
	closedir(dir);
	return count;
}

static int write_file(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (write(fd, "data", 4) != 4) {
		close(fd);
		return -1;
	}
	return close(fd);
}

static int read_file(const char *path)
{
	char buffer[8];
	ssize_t size;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	size = read(fd, buffer, sizeof(buffer));
	close(fd);
	return size == 4 && memcmp(buffer, "data", 4) == 0 ? 0 : -1;
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

static void mounter_exits(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0)
		_exit(mount("none", at("a"), "tmpfs", 0, NULL) < 0);
	wait_child(pid);

	CHECK(tmpfs_count() == 1);
	CHECK(write_file(at("a/file")) == 0);
	CHECK(read_file(at("a/file")) == 0);

	CHECK(umount(at("a")) == 0);
	CHECK(tmpfs_count() == 0);
	CHECK(access(at("a/file"), F_OK) < 0);
}

/* A bind mount of a directory of the tmpfs keeps it in use.  */
static void unmounted(void)
{
	CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
	CHECK(mkdir(at("a/sub"), 0700) == 0);
	CHECK(write_file(at("a/sub/file")) == 0);
	CHECK(mount(at("a/sub"), at("b"), NULL, MS_BIND, NULL) == 0);

	CHECK(umount(at("a")) == 0);
	CHECK(tmpfs_count() == 1);
	CHECK(read_file(at("b/file")) == 0);

	CHECK(umount(at("b")) == 0);
	CHECK(tmpfs_count() == 0);
}

/* PRoot replaces a binding with the one mounted over it.  */
static void mounted_over(void)
{
	CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
	CHECK(write_file(at("a/file")) == 0);
	CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
	CHECK(access(at("a/file"), F_OK) < 0);
	CHECK(tmpfs_count() == 1);

	CHECK(umount(at("a")) == 0);
	CHECK(tmpfs_count() == 0);
}

/* A copy of the mount in another mount name-space outlives the
 * original and the tracee that mounted it.  */
static void other_name_space(void)
{
	int c2m[2], m2c[2], g2m[2], m2g[2];
	pid_t mounter, other;

	CHECK(pipe(c2m) == 0 && pipe(m2c) == 0 && pipe(g2m) == 0 && pipe(m2g) == 0);

	mounter = fork();
	if (mounter == 0) {
		failed = 0;
		CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
		CHECK(write_file(at("a/file")) == 0);
		post(c2m[1]);
		fetch(m2c[0]);
		CHECK(umount(at("a")) == 0);
		_exit(failed);
	}
	fetch(c2m[0]);

	other = fork();
	if (other == 0) {
		failed = 0;
		CHECK(unshare(CLONE_NEWNS) == 0);
		post(g2m[1]);
		fetch(m2g[0]);
		CHECK(read_file(at("a/file")) == 0);
		_exit(failed);
	}
	fetch(g2m[0]);

	post(m2c[1]);
	wait_child(mounter);
	CHECK(access(at("a/file"), F_OK) < 0);
	CHECK(tmpfs_count() == 1);

	post(m2g[1]);
	wait_child(other);
	CHECK(tmpfs_count() == 0);

	close(c2m[0]); close(c2m[1]); close(m2c[0]); close(m2c[1]);
	close(g2m[0]); close(g2m[1]); close(m2g[0]); close(m2g[1]);
}

/* Only the new root binding leads to the tmpfs after chroot(2).  */
static void chroot_into(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		failed = 0;
		CHECK(unshare(CLONE_NEWNS) == 0);
		CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
		CHECK(write_file(at("a/file")) == 0);
		CHECK(chroot(at("a")) == 0);
		CHECK(chdir("/") == 0);
		CHECK(read_file("/file") == 0);
		CHECK(write_file("/other") == 0);
		CHECK(read_file("/other") == 0);
		_exit(failed);
	}
	wait_child(pid);
	CHECK(tmpfs_count() == 0);
}

/* As bubblewrap does.  */
static void pivot_into(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		failed = 0;
		CHECK(unshare(CLONE_NEWNS) == 0);
		CHECK(mount("none", at("a"), "tmpfs", 0, NULL) == 0);
		CHECK(chdir(at("a")) == 0);
		CHECK(mkdir("newroot", 0755) == 0);
		CHECK(mount("newroot", "newroot", NULL, MS_BIND, NULL) == 0);
		CHECK(mkdir("oldroot", 0755) == 0);
		CHECK(syscall(SYS_pivot_root, at("a"), "oldroot") == 0);
		CHECK(chdir("/") == 0);
		CHECK(write_file("/newroot/file") == 0);
		CHECK(umount2("oldroot", MNT_DETACH) == 0);

		CHECK(chdir("/newroot") == 0);
		CHECK(syscall(SYS_pivot_root, ".", ".") == 0);
		CHECK(umount2(".", MNT_DETACH) == 0);
		CHECK(chdir("/") == 0);
		CHECK(read_file("/file") == 0);
		CHECK(write_file("/other") == 0);
		CHECK(read_file("/other") == 0);
		_exit(failed);
	}
	wait_child(pid);
	CHECK(tmpfs_count() == 0);
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

	/* Where PRoot creates the directories of the tmpfs, see
	 * create_temp_name().  */
	if (realpath(proot_tmpdir ? proot_tmpdir : P_tmpdir, temp_directory) == NULL) {
		perror("realpath");
		exit(EXIT_FAILURE);
	}
	snprintf(prefix, sizeof(prefix), "proot-tmpfs--%d-", getppid());

	snprintf(base, sizeof(base), "%s/test-73e09cd8-XXXXXX", tmpdir ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	if (mkdir(at("a"), 0700) < 0 || mkdir(at("b"), 0700) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	mounter_exits();
	unmounted();
	mounted_over();
	other_name_space();
	chroot_into();
	pivot_into();

	CHECK(rmdir(at("a")) == 0);
	CHECK(rmdir(at("b")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
