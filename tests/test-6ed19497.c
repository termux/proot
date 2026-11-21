/* Bindings and emulated mounts at a name that ends with a dot, as
 * "foo." or "foo..", are made at this very name, and the chroot(2)
 * emulated with -0 works there.  The "/." and "/" a canonical path
 * may end with are still dropped.  */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char dir[PATH_MAX / 2];
static int failures;

#define CHECK(condition) do {						\
		if (!(condition)) {					\
			fprintf(stderr, "%s:%d: %s failed (errno: %s)\n", \
				__FILE__, __LINE__, #condition, strerror(errno)); \
			failures++;					\
		}							\
	} while (0)

static const char *at(const char *name)
{
	static char paths[4][PATH_MAX];
	static int next;
	char *path = paths[next++ % 4];

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	return path;
}

static int exists(const char *name)
{
	struct stat statl;

	return lstat(at(name), &statl) == 0;
}

/* Bind "src" at @target, check it is visible through @target only,
 * then unmount it through @untarget.  */
static void bind_at(const char *target, const char *other, const char *untarget)
{
	char file[PATH_MAX];

	snprintf(file, sizeof(file), "%s/file", target);

	CHECK(mount(at("src"), at(target), NULL, MS_BIND, NULL) == 0);
	CHECK(exists(file));
	CHECK(exists("src/file"));
	CHECK(exists(target));
	if (other != NULL) {
		snprintf(file, sizeof(file), "%s/file", other);
		CHECK(!exists(file));
	}

	CHECK(umount2(at(untarget), 0) == 0);
	snprintf(file, sizeof(file), "%s/file", target);
	CHECK(!exists(file));
}

int main(int argc, char *argv[])
{
	const char *tmpdir = getenv("TMPDIR");
	const char *names[] = { "src", "a.", "a..", "a", "b", "c", "t.", "c." };
	int with_fake_id0 = argc > 1 && strcmp(argv[1], "-0") == 0;
	size_t i;
	int fd;

	/* The binding given on the command line.  */
	CHECK(access("/bin./true", X_OK) == 0);
	CHECK(access("/bin/true", X_OK) == 0);
	CHECK(access("/bi", F_OK) < 0 && errno == ENOENT);

	/* PRoot emulates mount(2), it never fails it with EPERM.  A
	 * seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM)
		exit(failures == 0 ? 125 : EXIT_FAILURE);

	/* TMPDIR is a host path, it may not exist in the guest rootfs.  */
	if (tmpdir == NULL || access(tmpdir, W_OK) < 0)
		tmpdir = "/tmp";
	snprintf(dir, sizeof(dir), "%s/test-6ed19497-%d", tmpdir, getpid());

	if (mkdir(dir, 0700) < 0) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		CHECK(mkdir(at(names[i]), 0700) == 0);

	fd = open(at("src/file"), O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0);
	close(fd);
	fd = open(at("c./marker"), O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0);
	close(fd);

	/* Used to be bound at "a" or over the parent directory.  */
	bind_at("a.", "a", "a.");
	bind_at("a..", "a", "a..");

	/* The final "/." and "/" are not part of the name.  */
	bind_at("b/.", NULL, "b");
	bind_at("c/", NULL, "c");
	bind_at("c", NULL, "c/.");

	/* An emulated tmpfs: it used to replace the parent directory.  */
	CHECK(mount("tmpfs", at("t."), "tmpfs", 0, NULL) == 0);
	CHECK(exists("src/file"));
	fd = open(at("t./inside"), O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0);
	close(fd);
	CHECK(exists("t./inside"));
	CHECK(umount2(at("t."), 0) == 0);
	CHECK(!exists("t./inside"));

	/* chroot(2) as emulated with -0: it used to take a binding next
	 * to the new root for one inside it, and failed with EPERM.  */
	if (with_fake_id0) {
		pid_t pid;
		int status;

		CHECK(mount(at("src"), at("a"), NULL, MS_BIND, NULL) == 0);
		pid = fork();
		if (pid == 0)
			_exit(chroot(at("c.")) == 0 && access("/marker", F_OK) == 0
			      ? EXIT_SUCCESS : EXIT_FAILURE);
		CHECK(pid > 0 && waitpid(pid, &status, 0) == pid
		      && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(umount2(at("a"), 0) == 0);
	}
	CHECK(unlink(at("c./marker")) == 0);

	CHECK(unlink(at("src/file")) == 0);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		CHECK(rmdir(at(names[i])) == 0);
	CHECK(rmdir(dir) == 0);

	return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
