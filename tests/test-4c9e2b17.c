/* With -0, chroot(2) is emulated by replacing the bindings with the
 * new root, unless one of them lies under it.  When the kernel
 * reported the failure (no outer seccomp policy), that check compared
 * the bindings with an uninitialized guest path, which aborted PRoot
 * as soon as there was a binding other than the root, like "-b /proc"
 * here.  It also compared them with the path as given, so a relative
 * path, or one with ".." or a symbolic link, missed the bindings under
 * the new root.  */

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
#include <sys/wait.h>

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
	static char path[4][PATH_MAX];
	static int i;

	i = (i + 1) % 4;
	snprintf(path[i], sizeof(path[i]), "%s/%s", base, name);
	return path[i];
}

/* PRoot emulates chroot(2) only when the kernel refuses it.  */
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

/* A binding under the new root isn't supported: such a chroot(2)
 * fails, rather than losing the binding.  It fails with EPERM when
 * the kernel refused it first, with ENOSYS when an outer seccomp
 * policy did (SIGSYS).  */
static void unsupported(const char *path)
{
	errno = 0;
	CHECK(chroot(path) < 0 && (errno == EPERM || errno == ENOSYS));
	CHECK(access(at("root/sub/deeper"), F_OK) < 0);
}

static void binding_under_root(void)
{
	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount(at("empty"), at("root/sub"), NULL, MS_BIND, NULL) == 0);
	CHECK(chdir(base) == 0);

	unsupported(at("root"));
	unsupported("root");
	unsupported("./root/../root/");
	unsupported(at("link"));
	CHECK(chdir(at("root")) == 0);
	unsupported(".");
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

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	int fd;

	if (really_root())
		exit(125);

	snprintf(base, sizeof(base), "%s/test-4c9e2b17-XXXXXX", tmpdir ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	if (   mkdir(at("root"), 0700) < 0 || mkdir(at("root/sub"), 0700) < 0
	    || mkdir(at("empty"), 0700) < 0 || mkdir(at("alias"), 0700) < 0
	    || (fd = creat(at("root/inside"), 0600)) < 0 || close(fd) < 0
	    || (fd = creat(at("root/sub/deeper"), 0600)) < 0 || close(fd) < 0
	    || (fd = creat(at("file"), 0600)) < 0 || close(fd) < 0
	    || symlink("root", at("link")) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	in_child(absolute);
	in_child(relative);
	in_child(symlink_);
	/* PRoot emulates these syscalls, it never fails them with
	 * EPERM.  A seccomp filter of the environment does (the default
	 * profile of Docker), which PRoot can't override but by tracing
	 * every syscall (PROOT_NO_SECCOMP).  */
	if (   !(unshare(0) < 0 && errno == EPERM)
	    && !(mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM)) {
		in_child(bound_root);
		in_child(binding_under_root);
	}
	in_child(errors);

	CHECK(unlink(at("link")) == 0);
	CHECK(unlink(at("file")) == 0);
	CHECK(unlink(at("root/sub/deeper")) == 0);
	CHECK(unlink(at("root/inside")) == 0);
	CHECK(rmdir(at("root/sub")) == 0);
	CHECK(rmdir(at("root")) == 0);
	CHECK(rmdir(at("empty")) == 0);
	CHECK(rmdir(at("alias")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
