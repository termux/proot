/* PRoot emulates chroot(2) by replacing the bindings with the new
 * root and the bindings below it.
 *
 * - With -0, when the kernel reported the failure (no outer seccomp
 *   policy), the bindings were compared with an uninitialized guest
 *   path, which aborted PRoot as soon as there was a binding other
 *   than the root, like "-b /proc" here.  They were also compared
 *   with the path as given, so a relative path, or one with ".." or a
 *   symbolic link, missed the bindings below the new root.
 *
 * - A binding below the new root wasn't supported: such a chroot(2)
 *   failed, with EPERM when the kernel refused it first, with ENOSYS
 *   when an outer seccomp policy did (SIGSYS).
 *
 * - When the kernel permitted it (PRoot run by root), the kernel made
 *   chroot(2) itself: the host paths PRoot passes it were looked up
 *   from the new root then, none of them was found anymore.  */

#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/capability.h>

#define SIZE (PATH_MAX / 2)

static char base[SIZE];
static int failed;
static int with_fake_id0;

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

/* Run @scenario in a child: chroot(2) changes the root of the
 * calling process only.  */
static void in_child(void (*scenario)(void))
{
	int status = -1;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		failed = 0;
		scenario();
		_exit(failed);
	}
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void absolute(void)
{
	char cwd[PATH_MAX];

	CHECK(chdir(at("root/sub")) == 0);
	CHECK(chroot(at("root")) == 0);
	CHECK(access("/inside", F_OK) == 0);
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/sub") == 0);

	/* The binding of "/proc" isn't below the new root.  */
	errno = 0;
	CHECK(access("/proc", F_OK) < 0 && errno == ENOENT);

	/* Nested.  */
	CHECK(chroot("/sub") == 0);
	CHECK(access("/deeper", F_OK) == 0);
	CHECK(access("/inside", F_OK) < 0);
}

static void relative(void)
{
	CHECK(chdir(base) == 0);
	CHECK(chroot("./root/../root/") == 0);
	CHECK(access("/inside", F_OK) == 0);
}

static void symlink_(void)
{
	CHECK(chroot(at("link")) == 0);
	CHECK(access("/inside", F_OK) == 0);
}

/* The new root is a bind mount itself.  The scenarios that mount use
 * a mount namespace of their own, so the other ones don't see it.  */
static void bound_root(void)
{
	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount(at("root"), at("alias"), NULL, MS_BIND, NULL) == 0);
	CHECK(chroot(at("alias")) == 0);
	CHECK(access("/inside", F_OK) == 0);
}

/* A binding below the new root moves along with it.  */
static const char *new_root;

static void below_root(void)
{
	char cwd[PATH_MAX];
	int fd;

	CHECK(chroot(new_root) == 0);
	CHECK(access("/inside", F_OK) == 0);
	errno = 0;
	CHECK(access("/sub/deeper", F_OK) < 0 && errno == ENOENT);

	/* Through the binding, into the directory it leads to.  */
	CHECK(chdir("/sub") == 0);
	fd = creat("bound", 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/sub") == 0);
}

static void binding_below_root(void)
{
	char cwd[PATH_MAX];

	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount(at("empty"), at("root/sub"), NULL, MS_BIND, NULL) == 0);
	CHECK(chdir(base) == 0);

	new_root = at("root");
	in_child(below_root);
	CHECK(unlink(at("empty/bound")) == 0);
	new_root = "root";
	in_child(below_root);
	CHECK(unlink(at("empty/bound")) == 0);
	new_root = "./root/../root/";
	in_child(below_root);
	CHECK(unlink(at("empty/bound")) == 0);
	new_root = at("link");
	in_child(below_root);
	CHECK(unlink(at("empty/bound")) == 0);
	CHECK(chdir(at("root")) == 0);
	new_root = ".";
	in_child(below_root);
	CHECK(unlink(at("empty/bound")) == 0);

	/* The working directory lies in the binding.  */
	CHECK(chdir(at("root/sub")) == 0);
	CHECK(chroot(at("root")) == 0);
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/sub") == 0);
	CHECK(access("deeper", F_OK) < 0);
}

static void errors(void)
{
	errno = 0;
	CHECK(chroot("") < 0 && errno == ENOENT);
	errno = 0;
	CHECK(chroot(at("nonexistent")) < 0 && errno == ENOENT);
	errno = 0;
	CHECK(chroot(at("file")) < 0 && errno == ENOTDIR);
}

/* The user PRoot runs as: /proc doesn't tell the emulated one.  */
static int really_root(void)
{
	char line[256];
	int uid = -1;
	FILE *file;

	file = fopen("/proc/self/status", "r");
	if (file == NULL)
		return 0;
	while (fgets(line, sizeof(line), file) != NULL)
		if (sscanf(line, "Uid: %d", &uid) == 1)
			break;
	fclose(file);
	return uid == 0;
}

/* Without the privilege, chroot(2) fails with EPERM, once the path
 * is checked.  With -0, setuid(2) is emulated.  Otherwise, as root,
 * only CAP_SYS_CHROOT is dropped: setuid(2) would make the process
 * non-dumpable, PRoot couldn't read its memory anymore without
 * CAP_SYS_PTRACE (Docker).  */
static void unprivileged(void)
{
	if (with_fake_id0)
		CHECK(setuid(65534) == 0);
	else if (geteuid() == 0) {
		struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
		struct __user_cap_data_struct data[2];

		CHECK(syscall(SYS_capget, &header, data) == 0);
		data[CAP_SYS_CHROOT / 32].effective &= ~(1U << (CAP_SYS_CHROOT % 32));
		CHECK(syscall(SYS_capset, &header, data) == 0);
	}

	errno = 0;
	CHECK(chroot(at("root")) < 0 && errno == EPERM);
	errors();

	/* Root may search any directory.  */
	errno = 0;
	CHECK(chroot(at("closed")) < 0 && errno == (really_root() ? EPERM : EACCES));
}

int main(int argc, char *argv[])
{
	const char *tmpdir = getenv("TMPDIR");
	int fd;

	with_fake_id0 = argc > 1 && strcmp(argv[1], "-0") == 0;

	snprintf(base, sizeof(base), "%s/test-4c9e2b17-XXXXXX", tmpdir ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	if (   mkdir(at("root"), 0700) < 0 || mkdir(at("root/sub"), 0700) < 0
	    || mkdir(at("empty"), 0700) < 0 || mkdir(at("alias"), 0700) < 0
	    || mkdir(at("closed"), 0600) < 0
	    || (fd = creat(at("root/inside"), 0600)) < 0 || close(fd) < 0
	    || (fd = creat(at("root/sub/deeper"), 0600)) < 0 || close(fd) < 0
	    || (fd = creat(at("file"), 0600)) < 0 || close(fd) < 0
	    || symlink("root", at("link")) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	/* chroot(2) needs -0, or PRoot run by root.  */
	if (geteuid() == 0) {
		in_child(absolute);
		in_child(relative);
		in_child(symlink_);
		/* PRoot emulates these syscalls, it never fails them
		 * with EPERM.  A seccomp filter of the environment does
		 * (the default profile of Docker), which PRoot can't
		 * override but by tracing every syscall
		 * (PROOT_NO_SECCOMP).  */
		if (   !(unshare(0) < 0 && errno == EPERM)
		    && !(mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM)) {
			in_child(bound_root);
			in_child(binding_below_root);
		}
		in_child(errors);
	}
	in_child(unprivileged);

	CHECK(unlink(at("link")) == 0);
	CHECK(unlink(at("file")) == 0);
	CHECK(unlink(at("root/sub/deeper")) == 0);
	CHECK(unlink(at("root/inside")) == 0);
	CHECK(rmdir(at("root/sub")) == 0);
	CHECK(rmdir(at("root")) == 0);
	CHECK(rmdir(at("empty")) == 0);
	CHECK(rmdir(at("alias")) == 0);
	CHECK(rmdir(at("closed")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
