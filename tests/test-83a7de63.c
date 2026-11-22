/* The working directory as bubblewrap sees it when started from below
 * "/tmp": it mounts its base tmpfs on "/tmp", then asks for the working
 * directory, to go back there from the sandbox if it can, with
 * get_current_dir_name(3) -- which bionic doesn't have, that is
 * getcwd(2) once $PWD no longer leads to the working directory, as
 * under the mount.  The kernel
 * keeps the directory a mount covers as the working directory, and
 * getcwd(2) keeps reporting its path.  PRoot reported none, and as it
 * made chdir(NULL) succeed, bubblewrap went on with a NULL path and
 * crashed in setenv("PWD").  */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define SIZE (PATH_MAX / 2)

static char base[SIZE];
static int failed;

#define CHECK(condition) do {						\
		if (!(condition)) {					\
			fprintf(stderr, "%s:%d: %s failed (errno: %s)\n", \
				__FILE__, __LINE__, #condition, strerror(errno)); \
			failed = 1;					\
		}							\
	} while (0)

static const char *at(const char *name)
{
	static char paths[4][PATH_MAX];
	static int next;
	char *path = paths[next++ % 4];

	snprintf(path, PATH_MAX, "%s/%s", base, name);
	return path;
}

static int cwd_is(const char *expected)
{
	char cwd[PATH_MAX];

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return 0;

	if (strcmp(cwd, expected) != 0) {
		fprintf(stderr, "cwd: \"%s\" instead of \"%s\"\n", cwd, expected);
		return 0;
	}

	return 1;
}

/* What bubblewrap does from @base/w/cwd with "--bind / /".  */
static void sandbox(void)
{
	CHECK(chdir(at("w/cwd")) == 0);
	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == 0);
	CHECK(mount("tmpfs", at("w"), "tmpfs", MS_NODEV | MS_NOSUID, NULL) == 0);
	CHECK(cwd_is(at("w/cwd")));

	/* Its path leads under the mount now.  */
	CHECK(access(at("w/cwd"), F_OK) < 0 && errno == ENOENT);
	CHECK(chdir(at("w")) == 0);
	CHECK(cwd_is(at("w")));
	CHECK(chdir("cwd") < 0 && errno == ENOENT);
	CHECK(cwd_is(at("w")));

	/* The directory left, getcwd(2) is about the new one, which
	 * may be removed in turn.  */
	CHECK(mkdir(at("w/sub"), 0700) == 0);
	CHECK(chdir(at("w/sub")) == 0);
	CHECK(rmdir(at("w/sub")) == 0);
	CHECK(!cwd_is(at("w/sub")) && errno == ENOENT);
	CHECK(chdir("/") == 0);
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	char cwd[PATH_MAX];
	pid_t pid;
	int status = 0;

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (   (unshare(0) < 0 && errno == EPERM)
	    || (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM))
		exit(125);

	/* TMPDIR is a host path, it may not exist in the guest rootfs.  */
	snprintf(base, sizeof(base), "%s/test-83a7de63-XXXXXX",
		 tmpdir != NULL && access(tmpdir, W_OK) == 0 ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}
	CHECK(mkdir(at("w"), 0700) == 0);
	CHECK(mkdir(at("w/cwd"), 0700) == 0);

	/* chdir(2) of no path at all.  */
	CHECK(syscall(SYS_chdir, NULL) < 0 && errno == EFAULT);
	CHECK(syscall(SYS_chdir, "") < 0 && errno == ENOENT);

	/* The working directory removed is gone indeed.  */
	CHECK(mkdir(at("gone"), 0700) == 0);
	CHECK(chdir(at("gone")) == 0);
	CHECK(rmdir(at("gone")) == 0);
	CHECK(getcwd(cwd, sizeof(cwd)) == NULL && errno == ENOENT);
	CHECK(chdir("/") == 0);

	pid = fork();
	if (pid == 0) {
		failed = 0;
		sandbox();
		_exit(failed);
	}
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	CHECK(rmdir(at("w/cwd")) == 0);
	CHECK(rmdir(at("w")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
