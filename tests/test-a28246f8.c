/* The two pivot_root(2) of bubblewrap, with or without a tmpfs over
 * the directory it pivots into first ("--tmpfs /tmp" as bubblewrap
 * mounts its base on "/tmp"), as seen from the sandbox: the working
 * directory, the descriptor to the old root pivot_root(".", ".")
 * stacks over the new one, and the base directory itself.  */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
	struct stat statl;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return 0;

	if (strcmp(cwd, expected) != 0) {
		fprintf(stderr, "cwd: \"%s\" instead of \"%s\"\n", cwd, expected);
		return 0;
	}

	return stat(".", &statl) == 0 && S_ISDIR(statl.st_mode);
}

static int fd_is(int fd, const char *expected)
{
	char link[64];
	char path[PATH_MAX];
	ssize_t length;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	length = readlink(link, path, sizeof(path) - 1);
	if (length < 0)
		return 0;
	path[length] = '\0';

	if (strcmp(path, expected) != 0) {
		fprintf(stderr, "fd %d: \"%s\" instead of \"%s\"\n", fd, path, expected);
		return 0;
	}

	return 1;
}

static int compare_names(const void *a, const void *b)
{
	return strcmp(*(char * const *) a, *(char * const *) b);
}

/* The sorted names in @path, but "." and "..", separated with spaces.  */
static const char *names(const char *path)
{
	static char list[PATH_MAX];
	char *entries[16];
	struct dirent *entry;
	size_t count = 0;
	size_t i;
	DIR *dir;

	list[0] = '\0';
	dir = opendir(path);
	if (dir == NULL)
		return "<none>";

	while ((entry = readdir(dir)) != NULL && count < 16) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;
		entries[count++] = strdup(entry->d_name);
	}
	closedir(dir);

	qsort(entries, count, sizeof(entries[0]), compare_names);
	for (i = 0; i < count; i++) {
		if (i > 0)
			strncat(list, " ", sizeof(list) - strlen(list) - 1);
		strncat(list, entries[i] != NULL ? entries[i] : "?",
			sizeof(list) - strlen(list) - 1);
		free(entries[i]);
	}

	return list;
}

static int names_are(const char *path, const char *expected)
{
	const char *list = names(path);

	if (strcmp(list, expected) != 0) {
		fprintf(stderr, "%s: \"%s\" instead of \"%s\"\n", path, list, expected);
		return 0;
	}

	return 1;
}

static int write_file(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

/* What bubblewrap does for "--bind / /", and "--tmpfs W" if
 * @tmpfs_over_base, with W its base directory ("/tmp" usually).  */
static void sandbox(int tmpfs_over_base)
{
	char newroot_base[SIZE + 16];
	int old_root_fd;

	snprintf(newroot_base, sizeof(newroot_base), "/newroot%s", at("w"));

	CHECK(unshare(CLONE_NEWNS) == 0);
	CHECK(mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == 0);
	CHECK(mount("tmpfs", at("w"), "tmpfs", MS_NODEV | MS_NOSUID, NULL) == 0);
	CHECK(chdir(at("w")) == 0);
	CHECK(mkdir("newroot", 0755) == 0);
	CHECK(mount("newroot", "newroot", NULL, MS_BIND | MS_REC, NULL) == 0);
	CHECK(mkdir("oldroot", 0755) == 0);

	/* The working directory is the new root.  */
	CHECK(syscall(SYS_pivot_root, at("w"), "oldroot") == 0);
	CHECK(cwd_is("/"));
	CHECK(chdir("/") == 0);
	CHECK(names_are("/", "newroot oldroot"));

	/* Bubblewrap 0.11 and earlier mount paths.  */
	CHECK(mount("/oldroot", "/newroot", NULL, MS_BIND | MS_REC, NULL) == 0);
	if (tmpfs_over_base)
		CHECK(mount("tmpfs", newroot_base, "tmpfs", MS_NODEV | MS_NOSUID, NULL) == 0);

	/* The second pivot.  */
	CHECK(umount2("oldroot", MNT_DETACH) == 0);
	old_root_fd = open("/", O_DIRECTORY | O_RDONLY);
	CHECK(old_root_fd >= 0);
	CHECK(chdir("/newroot") == 0);
	CHECK(syscall(SYS_pivot_root, ".", ".") == 0);
	CHECK(cwd_is("/"));

	/* The old root is stacked over the new one.  */
	CHECK(fd_is(old_root_fd, "/"));
	CHECK(fchdir(old_root_fd) == 0);
	CHECK(getcwd(newroot_base, sizeof(newroot_base)) != NULL
	      && strcmp(newroot_base, "/") == 0);
	CHECK(umount2(".", MNT_DETACH) == 0);
	CHECK(chdir("/") == 0);
	close(old_root_fd);
	CHECK(cwd_is("/"));

	/* Neither the base nor the new root remain mounted elsewhere.  */
	CHECK(access("/newroot", F_OK) < 0 && errno == ENOENT);
	CHECK(access("/oldroot", F_OK) < 0 && errno == ENOENT);
	if (tmpfs_over_base) {
		CHECK(names_are(at("w"), ""));
		CHECK(write_file(at("w/inside")) == 0);
		CHECK(names_are(at("w"), "inside"));
	}
	else
		CHECK(names_are(at("w"), "marker"));
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	int tmpfs_over_base;

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (   (unshare(0) < 0 && errno == EPERM)
	    || (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM))
		exit(125);

	/* TMPDIR is a host path, it may not exist in the guest rootfs.  */
	snprintf(base, sizeof(base), "%s/test-a28246f8-XXXXXX",
		 tmpdir != NULL && access(tmpdir, W_OK) == 0 ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}
	CHECK(mkdir(at("w"), 0700) == 0);
	CHECK(write_file(at("w/marker")) == 0);

	for (tmpfs_over_base = 0; tmpfs_over_base <= 1; tmpfs_over_base++) {
		pid_t pid;
		int status = 0;

		pid = fork();
		if (pid == 0) {
			failed = 0;
			sandbox(tmpfs_over_base);
			_exit(failed);
		}
		CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

		/* The sandbox has a mount name-space of its own.  */
		CHECK(names_are(at("w"), "marker"));
	}

	CHECK(unlink(at("w/marker")) == 0);
	CHECK(rmdir(at("w")) == 0);
	CHECK(rmdir(base) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
