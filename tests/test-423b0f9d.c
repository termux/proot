/* Since version 0.12, bubblewrap opens the files of its sandbox with
 * openat2(2) and RESOLVE_IN_ROOT, then mounts through the descriptors
 * it got: mount("/proc/self/fd/<SOURCE>", "/proc/self/fd/<TARGET>").
 * Under PRoot:
 *
 * - RESOLVE_IN_ROOT was ignored, so absolute paths, absolute symbolic
 *   links and ".." were resolved against the root of the tracee rather
 *   than against the directory given;
 *
 * - the emulation of mount(2) bound the "/proc/<PID>/fd/<FD>" links
 *   themselves rather than the files they refer to;
 *
 * - the directory a descriptor refers to was told by the first guest
 *   path leading there, whatever guest path it was opened through:
 *   once "/" is bound in the new root, "/oldroot" and "/newroot" lead to
 *   the same host directory, but what is below them differs.  */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_IN_ROOT		0x10

struct how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

#define SIZE (PATH_MAX / 2)

static char base[SIZE];
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
	static char path[8][PATH_MAX];
	static int i;

	i = (i + 1) % 8;
	snprintf(path[i], sizeof(path[i]), "%s/%s", base, name);
	return path[i];
}

static int openat2_(int dir_fd, const char *path, int flags, uint64_t resolve)
{
	struct how how = { .flags = flags, .mode = 0600, .resolve = resolve };

	return syscall(SYS_openat2, dir_fd, path, &how, sizeof(how));
}

/* "/proc/self/fd/@fd", as bubblewrap names it.  */
static const char *fd_path(int fd)
{
	static char path[4][64];
	static int i;

	i = (i + 1) % 4;
	snprintf(path[i], sizeof(path[i]), "/proc/self/fd/%d", fd);
	return path[i];
}

/* Whether the descriptor @fd is told to refer to @expected.  */
static int fd_is(int fd, const char *expected)
{
	char link[PATH_MAX];
	ssize_t size;

	size = readlink(fd_path(fd), link, sizeof(link) - 1);
	if (size < 0)
		return 0;
	link[size] = '\0';

	if (strcmp(link, expected) != 0) {
		fprintf(stderr, "fd %d: \"%s\" instead of \"%s\"\n", fd, link, expected);
		return 0;
	}
	return 1;
}

static int write_file(const char *path, const char *content)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (write(fd, content, strlen(content)) != (ssize_t) strlen(content)) {
		close(fd);
		return -1;
	}
	return close(fd);
}

/* Whether the file the descriptor @fd refers to, or the file @path if
 * @fd is negative, contains @content.  */
static int contains(int fd, const char *path, const char *content)
{
	char buffer[64];
	ssize_t size;

	if (fd < 0)
		fd = open(path, O_RDONLY);
	else
		fd = dup(fd);
	if (fd < 0)
		return 0;
	size = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (size < 0)
		return 0;
	buffer[size] = '\0';
	return strcmp(buffer, content) == 0;
}

/* The path is resolved in the directory given, as if it were "/".  */
static void in_root(void)
{
	char path[PATH_MAX];
	struct stat statl;
	int root_fd;
	int proc_fd;
	int fd;

	CHECK(mkdir(at("root"), 0700) == 0);
	CHECK(mkdir(at("root/sub"), 0700) == 0);
	CHECK(write_file(at("root/file"), "file") == 0);
	CHECK(write_file(at("root/sub/inner"), "inner") == 0);
	CHECK(symlink("/sub", at("root/abs")) == 0);
	CHECK(symlink("../../..", at("root/sub/rel")) == 0);

	root_fd = open(at("root"), O_PATH | O_DIRECTORY);
	CHECK(root_fd >= 0);

	fd = openat2_(root_fd, "/file", O_RDONLY, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && contains(fd, NULL, "file"));
	close(fd);

	fd = openat2_(root_fd, "../../file", O_RDONLY, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && contains(fd, NULL, "file"));
	close(fd);

	fd = openat2_(root_fd, "/abs/inner", O_RDONLY, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && contains(fd, NULL, "inner"));
	CHECK(fd >= 0 && fd_is(fd, at("root/sub/inner")));
	close(fd);

	fd = openat2_(root_fd, "sub/rel/file", O_RDONLY, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && contains(fd, NULL, "file"));
	close(fd);

	fd = openat2_(root_fd, "abs", O_PATH | O_NOFOLLOW, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && fstatat(fd, "", &statl, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == 0
	      && S_ISLNK(statl.st_mode));
	close(fd);

	/* Created in the root as well.  */
	fd = openat2_(root_fd, "/abs/new", O_WRONLY | O_CREAT | O_EXCL, RESOLVE_IN_ROOT);
	CHECK(fd >= 0);
	close(fd);
	CHECK(access(at("root/sub/new"), F_OK) == 0);

	/* "/proc/self" leads to the "<PID>" next to it...  */
	proc_fd = open("/proc", O_PATH | O_DIRECTORY);
	CHECK(proc_fd >= 0);
	fd = openat2_(proc_fd, "self/status", O_RDONLY, RESOLVE_IN_ROOT);
	snprintf(path, sizeof(path), "/proc/%d/status", getpid());
	CHECK(fd >= 0 && fd_is(fd, path));
	close(fd);
	close(proc_fd);

	/* ... but the links of a process are "magic".  */
	proc_fd = open("/proc/self", O_PATH | O_DIRECTORY);
	CHECK(proc_fd >= 0);
	errno = 0;
	CHECK(openat2_(proc_fd, "exe", O_PATH, RESOLVE_IN_ROOT) < 0 && errno == EXDEV);
	errno = 0;
	CHECK(openat2_(proc_fd, "exe", O_PATH, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS) < 0
	      && errno == ELOOP);
	close(proc_fd);

	/* Nothing changes without RESOLVE_IN_ROOT.  */
	fd = openat2_(root_fd, "sub/inner", O_RDONLY, 0);
	CHECK(fd >= 0 && contains(fd, NULL, "inner"));
	close(fd);
	CHECK(openat2_(root_fd, "/file", O_RDONLY, 0) < 0 || access("/file", F_OK) == 0);

	close(root_fd);
}

/* Mount through descriptors opened through one of two guest paths that
 * lead to the same directory.  */
static void aliases(void)
{
	int file_fd;
	int src_fd;
	int b_fd;
	int d_fd;
	int e_fd;
	int fd;

	CHECK(mkdir(at("t"), 0700) == 0);
	CHECK(mkdir(at("t/d"), 0700) == 0);
	CHECK(mkdir(at("t/e"), 0700) == 0);
	CHECK(write_file(at("t/e/marker"), "e") == 0);
	CHECK(write_file(at("t/file"), "") == 0);
	CHECK(mkdir(at("src"), 0700) == 0);
	CHECK(write_file(at("src/marker"), "src") == 0);
	CHECK(write_file(at("srcfile"), "srcfile") == 0);
	CHECK(mkdir(at("a"), 0700) == 0);
	CHECK(mkdir(at("b"), 0700) == 0);
	CHECK(mount(at("t"), at("a"), NULL, MS_BIND, NULL) == 0);
	CHECK(mount(at("t"), at("b"), NULL, MS_BIND, NULL) == 0);

	b_fd = open(at("b"), O_PATH | O_DIRECTORY);
	CHECK(b_fd >= 0 && fd_is(b_fd, at("b")));

	d_fd = openat(b_fd, "d", O_PATH | O_NOFOLLOW);
	CHECK(d_fd >= 0 && fd_is(d_fd, at("b/d")));

	fd = openat2_(b_fd, "/d", O_PATH | O_NOFOLLOW, RESOLVE_IN_ROOT);
	CHECK(fd >= 0 && fd_is(fd, at("b/d")));
	close(fd);

	/* Reopened through its descriptor.  */
	fd = open(fd_path(d_fd), O_PATH);
	CHECK(fd >= 0 && fd_is(fd, at("b/d")));
	close(fd);

	/* Bind mount.  */
	src_fd = open(at("src"), O_PATH);
	CHECK(src_fd >= 0);
	CHECK(mount(fd_path(src_fd), fd_path(d_fd), NULL, MS_BIND, NULL) == 0);
	CHECK(contains(-1, at("b/d/marker"), "src"));
	CHECK(access(at("a/d/marker"), F_OK) < 0);
	close(src_fd);
	close(d_fd);

	/* Bind mount of a file.  */
	src_fd = open(at("srcfile"), O_PATH);
	file_fd = openat(b_fd, "file", O_PATH);
	CHECK(src_fd >= 0 && file_fd >= 0);
	CHECK(mount(fd_path(src_fd), fd_path(file_fd), NULL, MS_BIND, NULL) == 0);
	CHECK(contains(-1, at("b/file"), "srcfile"));
	CHECK(contains(-1, at("a/file"), ""));
	close(src_fd);
	close(file_fd);

	/* Tmpfs, then unmounted through a descriptor.  */
	e_fd = openat(b_fd, "e", O_PATH | O_DIRECTORY);
	CHECK(e_fd >= 0);
	CHECK(mount("tmpfs", fd_path(e_fd), "tmpfs", 0, NULL) == 0);
	CHECK(access(at("b/e/marker"), F_OK) < 0);
	CHECK(write_file(at("b/e/new"), "new") == 0);
	CHECK(contains(-1, at("a/e/marker"), "e"));
	close(e_fd);

	e_fd = openat(b_fd, "e", O_PATH | O_DIRECTORY);
	CHECK(e_fd >= 0 && fd_is(e_fd, at("b/e")));
	CHECK(umount2(fd_path(e_fd), MNT_DETACH) == 0);
	close(e_fd);
	CHECK(contains(-1, at("b/e/marker"), "e"));
	CHECK(access(at("b/e/new"), F_OK) < 0);

	close(b_fd);
}

/* Open @path in the root @root as bubblewrap does.  */
static int open_in_root(const char *root, const char *path, int flags)
{
	int root_fd;
	int fd;

	root_fd = open(root, O_PATH | O_CLOEXEC);
	if (root_fd < 0)
		return -1;
	fd = openat2_(root_fd, path, flags | O_CLOEXEC, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
	close(root_fd);
	return fd;
}

/* Bind mount the descriptor @src_fd on the descriptor @dest_fd as
 * bubblewrap does, @dest being the expected path of this latter.  */
static void bind_fds(int src_fd, int dest_fd, const char *dest)
{
	CHECK(fd_is(dest_fd, dest));
	CHECK(mount(fd_path(src_fd), fd_path(dest_fd), NULL, MS_BIND | MS_REC, NULL) == 0);
	close(src_fd);
	close(dest_fd);
}

/* What bubblewrap does for "--bind / / --tmpfs X --ro-bind Y X/file"
 * with X and Y below the base directory.  */
static void sandbox(void)
{
	char newroot_base[SIZE + 16];
	char path[PATH_MAX];
	int old_root_fd;
	int parent_fd;
	int dest_fd;
	int src_fd;
	int fd;

	CHECK(mkdir(at("w"), 0700) == 0);
	CHECK(mkdir(at("x"), 0700) == 0);
	CHECK(write_file(at("x/hidden"), "hidden") == 0);
	CHECK(write_file(at("y"), "y") == 0);

	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount("tmpfs", at("w"), "tmpfs", 0, NULL) == 0);
	CHECK(chdir(at("w")) == 0);
	CHECK(mkdir("newroot", 0755) == 0);
	CHECK(mount("newroot", "newroot", NULL, MS_BIND | MS_REC, NULL) == 0);
	CHECK(mkdir("oldroot", 0755) == 0);
	CHECK(syscall(SYS_pivot_root, at("w"), "oldroot") == 0);
	CHECK(chdir("/") == 0);

	/* --bind / /  */
	src_fd = open_in_root("/oldroot", "/", O_PATH);
	parent_fd = open_in_root("/newroot", "/", O_DIRECTORY);
	dest_fd = openat(parent_fd, ".", O_PATH | O_NOFOLLOW | O_CLOEXEC);
	CHECK(src_fd >= 0 && parent_fd >= 0 && dest_fd >= 0);
	bind_fds(src_fd, dest_fd, "/newroot");
	close(parent_fd);

	/* --tmpfs X: "/oldroot/X" and "/newroot/X" lead to the same host
	 * directory from now on.  */
	parent_fd = open_in_root("/newroot", base, O_DIRECTORY);
	CHECK(parent_fd >= 0);
	snprintf(newroot_base, sizeof(newroot_base), "/newroot%s", base);
	CHECK(fd_is(parent_fd, newroot_base));
	dest_fd = openat(parent_fd, "x", O_PATH | O_NOFOLLOW | O_CLOEXEC);
	CHECK(dest_fd >= 0);
	snprintf(path, sizeof(path), "%s/x", newroot_base);
	CHECK(fd_is(dest_fd, path));
	CHECK(mount("tmpfs", fd_path(dest_fd), "tmpfs", MS_NOSUID | MS_NODEV, NULL) == 0);
	close(dest_fd);
	close(parent_fd);

	/* --ro-bind Y X/file  */
	snprintf(path, sizeof(path), "%s/x", base);
	parent_fd = open_in_root("/newroot", path, O_DIRECTORY);
	CHECK(parent_fd >= 0);
	fd = openat(parent_fd, "file", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0444);
	CHECK(fd >= 0);
	close(fd);
	dest_fd = openat(parent_fd, "file", O_PATH | O_NOFOLLOW | O_CLOEXEC);
	src_fd = open_in_root("/oldroot", at("y"), O_PATH);
	CHECK(src_fd >= 0 && dest_fd >= 0);
	snprintf(path, sizeof(path), "%s/x/file", newroot_base);
	bind_fds(src_fd, dest_fd, path);
	close(parent_fd);

	/* The second pivot.  */
	CHECK(umount2("oldroot", MNT_DETACH) == 0);
	old_root_fd = open("/", O_DIRECTORY | O_RDONLY);
	CHECK(old_root_fd >= 0);
	CHECK(chdir("/newroot") == 0);
	CHECK(syscall(SYS_pivot_root, ".", ".") == 0);
	CHECK(fchdir(old_root_fd) == 0);
	CHECK(umount2(".", MNT_DETACH) == 0);
	CHECK(chdir("/") == 0);
	close(old_root_fd);

	CHECK(contains(-1, at("x/file"), "y"));
	CHECK(access(at("x/hidden"), F_OK) < 0);
	CHECK(write_file(at("x/other"), "other") == 0);
	CHECK(contains(-1, at("y"), "y"));
}

/* Remove the file @path, or the directory once its content is.  */
static int remove_entry(const char *path, const struct stat *statl, int type, struct FTW *ftw)
{
	(void) statl;
	(void) ftw;

	CHECK((type == FTW_DP ? rmdir(path) : unlink(path)) == 0);
	return 0;
}

/* Remove the base directory, once the mounts made below are undone:
 * removing the files through them would remove these files twice and
 * leave the mount points.  The sandbox made its own mounts in a mount
 * name-space of its own.  */
static void clean_up(void)
{
	CHECK(umount2(at("b/file"), MNT_DETACH) == 0);
	CHECK(umount2(at("b/d"), MNT_DETACH) == 0);
	CHECK(umount2(at("b"), MNT_DETACH) == 0);
	CHECK(umount2(at("a"), MNT_DETACH) == 0);

	CHECK(nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	pid_t pid;
	int status;

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (   (unshare(0) < 0 && errno == EPERM)
	    || (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM))
		exit(125);

	/* TMPDIR is a host path, it may not exist in the guest rootfs.  */
	snprintf(base, sizeof(base), "%s/test-423b0f9d-XXXXXX",
		 tmpdir != NULL && access(tmpdir, W_OK) == 0 ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	in_root();
	aliases();

	pid = fork();
	if (pid == 0) {
		failed = 0;
		sandbox();
		_exit(failed);
	}
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* The sandbox has a mount name-space of its own.  */
	CHECK(contains(-1, at("x/hidden"), "hidden"));
	CHECK(access(at("x/file"), F_OK) < 0);

	clean_up();

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
