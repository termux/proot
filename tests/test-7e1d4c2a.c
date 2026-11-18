/* PRoot emulates mount(2) by adding bindings, and the tracees used to
 * share them all: a mount made after unshare(CLONE_NEWNS), as sandbox
 * helpers do, changed what every other process saw.  A new mount
 * namespace starts with a copy of the bindings now, one that keeps
 * resolving paths as before.  unshare(CLONE_FS), which CLONE_NEWNS
 * implies, gives the caller a working directory of its own.
 *
 * Run without -r: of the bindings of a directory of the guest rootfs,
 * none is picked to tell where a file is.  */

#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define SIZE (PATH_MAX / 2)

static char base[SIZE], target[SIZE + 16], empty[SIZE + 16], workdir[SIZE + 16];
static char marker[SIZE + 32];
static int sync1[2], sync2[2];
static int failed;

#define CHECK(condition) do {						\
	if (!(condition)) {						\
		fprintf(stderr, "line %d: %s failed\n", __LINE__, #condition); \
		failed = 1;						\
	}								\
} while (0)

static int marker_visible(void)
{
	return access(marker, F_OK) == 0;
}

static int new_mount_ns(void)
{
	return unshare(CLONE_NEWNS) == 0
		&& mount(empty, target, NULL, MS_BIND, NULL) == 0;
}

static void wait_child(pid_t pid)
{
	int status;

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* Synchronization with other processes, also with those that can't
 * be waited for: these send their status.  */
static void post(int fd[2], char status)
{
	CHECK(write(fd[1], &status, 1) == 1);
}

static char fetch(int fd[2])
{
	char status = 1;

	CHECK(read(fd[0], &status, 1) == 1);
	return status;
}

static void *thread_new_mount_ns(void *unused)
{
	(void) unused;
	CHECK(new_mount_ns());
	CHECK(!marker_visible());
	return NULL;
}

static void *thread_chdir(void *unshared)
{
	if (unshared != NULL)
		CHECK(unshare(CLONE_FS) == 0);
	CHECK(chdir(workdir) == 0);
	return NULL;
}

static void cwd_after_thread(int unshared, const char *expected)
{
	char cwd[PATH_MAX];
	pthread_t thread;

	CHECK(chdir(base) == 0);
	CHECK(pthread_create(&thread, NULL, thread_chdir, unshared ? (void *) 1 : NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, expected) == 0);
}

/* Where the file opened at @path reads back to be.  */
static void opened_at(const char *path, char result[PATH_MAX])
{
	char link[64];
	ssize_t length;
	int fd;

	result[0] = '\0';
	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	length = readlink(link, result, PATH_MAX - 1);
	CHECK(length > 0);
	if (length > 0)
		result[length] = '\0';
	close(fd);
}

int main(void)
{
	char path[PATH_MAX], expected[PATH_MAX], result[PATH_MAX];
	const char *tmpdir = getenv("TMPDIR");
	pthread_t thread;
	pid_t pid;

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (   (unshare(0) < 0 && errno == EPERM)
	    || (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM))
		exit(125);

	snprintf(base, sizeof(base), "%s/test-7e1d4c2a-XXXXXX", tmpdir ?: "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	snprintf(target, sizeof(target), "%s/target", base);
	snprintf(empty, sizeof(empty), "%s/empty", base);
	snprintf(workdir, sizeof(workdir), "%s/workdir", base);
	snprintf(marker, sizeof(marker), "%s/marker", target);

	if (   mkdir(target, 0700) < 0 || mkdir(empty, 0700) < 0
	    || mkdir(workdir, 0700) < 0 || creat(marker, 0600) < 0
	    || pipe(sync1) < 0 || pipe(sync2) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	/* A sibling keeps its view, even once the process that made
	 * the mount is gone.  */
	pid = fork();
	if (pid == 0) {
		CHECK(new_mount_ns());
		CHECK(!marker_visible());
		post(sync1, failed);
		(void) fetch(sync2);
		_exit(failed);
	}
	CHECK(fetch(sync1) == 0);
	CHECK(marker_visible());
	post(sync2, 0);
	wait_child(pid);
	CHECK(marker_visible());

	/* So does another thread: threads share their file-system
	 * information (CLONE_FS).  */
	CHECK(pthread_create(&thread, NULL, thread_new_mount_ns, NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(marker_visible());

	/* Children forked before the mount keep the old view, those
	 * forked after share the new one, even once their parent is
	 * gone.  */
	pid = fork();
	if (pid == 0) {
		pid_t before = fork();
		if (before == 0) {
			(void) fetch(sync1);
			CHECK(marker_visible());
			_exit(failed);
		}
		CHECK(new_mount_ns());
		if (fork() == 0) {
			(void) fetch(sync2);
			CHECK(!marker_visible());
			post(sync1, failed);
			_exit(failed);
		}
		post(sync1, 0);
		wait_child(before);
		_exit(failed);
	}
	wait_child(pid);
	post(sync2, 0);
	CHECK(fetch(sync1) == 0);
	CHECK(marker_visible());

	/* Unmounting in the new namespace leaves the old one alone.  */
	snprintf(path, sizeof(path), "%s/bound", base);
	CHECK(mkdir(path, 0700) == 0);
	CHECK(mount(target, path, NULL, MS_BIND, NULL) == 0);
	pid = fork();
	if (pid == 0) {
		CHECK(unshare(CLONE_NEWNS) == 0);
		CHECK(umount(path) == 0);
		post(sync1, failed);
		(void) fetch(sync2);
		_exit(failed);
	}
	CHECK(fetch(sync1) == 0);
	snprintf(path, sizeof(path), "%s/bound/marker", base);
	CHECK(access(path, F_OK) == 0);
	post(sync2, 0);
	wait_child(pid);

	/* A pivot_root(2) in the namespace of a clone(CLONE_NEWNS)
	 * child, as bubblewrap does.  */
	pid = syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
	if (pid == 0) {
		char old_root[PATH_MAX];

		snprintf(path, sizeof(path), "%s/root", base);
		snprintf(old_root, sizeof(old_root), "%s/root/old", base);
		CHECK(mkdir(path, 0700) == 0 && mkdir(old_root, 0700) == 0);
		CHECK(mount(path, path, NULL, MS_BIND, NULL) == 0);
		CHECK(syscall(SYS_pivot_root, path, old_root) == 0);
		CHECK(chdir("/") == 0);
		snprintf(path, sizeof(path), "/old%s", marker);
		CHECK(access(path, F_OK) == 0);
		CHECK(!marker_visible());
		_exit(failed);
	}
	wait_child(pid);
	CHECK(marker_visible());

	/* Detaching from the shared working directory.  */
	cwd_after_thread(1, base);
	cwd_after_thread(0, workdir);

	/* Of two bindings of the same directory, the copy picks the
	 * same one to tell where a file is.  */
	snprintf(path, sizeof(path), "%s/alias1", base);
	CHECK(mkdir(path, 0700) == 0);
	CHECK(mount(target, path, NULL, MS_BIND, NULL) == 0);
	snprintf(path, sizeof(path), "%s/alias2", base);
	CHECK(mkdir(path, 0700) == 0);
	CHECK(mount(target, path, NULL, MS_BIND, NULL) == 0);
	snprintf(path, sizeof(path), "%s/alias2/marker", base);
	opened_at(path, expected);

	pid = syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
	if (pid == 0) {
		opened_at(path, result);
		CHECK(strcmp(result, expected) == 0);
		_exit(failed);
	}
	wait_child(pid);

	pid = fork();
	if (pid == 0) {
		CHECK(unshare(CLONE_NEWNS) == 0);
		opened_at(path, result);
		CHECK(strcmp(result, expected) == 0);
		_exit(failed);
	}
	wait_child(pid);

	/* The first process, the one the bindings belong to, can have
	 * a namespace of its own too.  */
	pid = fork();
	if (pid == 0) {
		(void) fetch(sync1);
		CHECK(marker_visible());
		_exit(failed);
	}
	CHECK(new_mount_ns());
	CHECK(!marker_visible());
	post(sync1, 0);
	wait_child(pid);

	/* Clean up.  */
	CHECK(umount(target) == 0);
	CHECK(unlink(marker) == 0);
	CHECK(chdir("/") == 0);
	const char *names[] = { "bound", "alias1", "alias2" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", base, names[i]);
		CHECK(umount(path) == 0 && rmdir(path) == 0);
	}
	const char *dirs[] = { target, empty, workdir, "root/old", "root", base };
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		if (dirs[i][0] == '/')
			snprintf(path, sizeof(path), "%s", dirs[i]);
		else
			snprintf(path, sizeof(path), "%s/%s", base, dirs[i]);
		CHECK(rmdir(path) == 0);
	}

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
