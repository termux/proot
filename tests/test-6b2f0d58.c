/* PRoot emulates mount(2) by adding a binding and umount(2) by
 * removing it, but a binding removed from the lists stayed allocated
 * until the context it was created in was freed, e.g. until the end of
 * the process that called mount(2): PRoot kept growing with every
 * mount(2) and umount(2), or mount(2) over the same path.
 *
 * Worse, pivot_root(2) went on using the bindings it had snapshotted
 * after inserting the rebased ones, while such an insertion frees the
 * binding it replaces when this one belongs to a list, as the bindings
 * set at PRoot startup do: "-b /proc" here, bound again under the new
 * root.  "make memcheck" catches this use after free.  */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define SIZE (PATH_MAX / 2)
#define CYCLES 2000

/* What a leaked binding costs at least: its two paths.  */
#define BINDING_KB (2 * PATH_MAX / 1024)

static char base[SIZE];
static int failed;

#define CHECK(condition) do {						\
	if (!(condition)) {						\
		fprintf(stderr, "line %d: %s failed (%s)\n", __LINE__,	\
			#condition, strerror(errno));			\
		failed = 1;						\
	}								\
} while (0)

/* Path @name below the base directory, as seen through @prefix.  */
static const char *at(const char *prefix, const char *name)
{
	static char path[4][PATH_MAX];
	static int i;

	i = (i + 1) % 4;
	snprintf(path[i], sizeof(path[i]), "%s%s/%s", prefix, base, name);
	return path[i];
}

/* Size in kB of the data of PRoot, the parent of this first tracee,
 * or -1 if that's not PRoot running natively (valgrind keeps freed
 * blocks aside).  */
static long tracer_data_kb(void)
{
	char path[64], line[256];
	long size = -1;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/comm", getppid());
	file = fopen(path, "r");
	if (file == NULL)
		return -1;
	if (fgets(line, sizeof(line), file) == NULL || strcmp(line, "proot\n") != 0)
		size = -2;
	fclose(file);
	if (size == -2)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/status", getppid());
	file = fopen(path, "r");
	if (file == NULL)
		return -1;
	while (fgets(line, sizeof(line), file) != NULL)
		if (sscanf(line, "VmData: %ld kB", &size) == 1)
			break;
	fclose(file);
	return size;
}

/* PRoot doesn't grow by a binding each mount(2) in @cycle.  */
static void check_growth(void (*cycle)(void), int unmount)
{
	long before, after;
	int i;

	/* Let the allocator reach its steady state.  */
	for (i = 0; i < 100; i++)
		cycle();

	before = tracer_data_kb();
	for (i = 0; i < CYCLES; i++)
		cycle();
	after = tracer_data_kb();

	if (unmount)
		CHECK(umount(at("", "target")) == 0);

	if (before >= 0 && after >= 0)
		CHECK(after - before < CYCLES * BINDING_KB / 4);
}

static void mount_umount(void)
{
	CHECK(mount(at("", "empty"), at("", "target"), NULL, MS_BIND, NULL) == 0);
	CHECK(access(at("", "target/marker"), F_OK) < 0);
	CHECK(umount(at("", "target")) == 0);
	CHECK(access(at("", "target/marker"), F_OK) == 0);
}

static void mount_over(void)
{
	CHECK(mount(at("", "empty"), at("", "target"), NULL, MS_BIND, NULL) == 0);
	CHECK(access(at("", "target/marker"), F_OK) < 0);
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	int fd;

	/* PRoot emulates these syscalls, it never fails them with EPERM.
	 * A seccomp filter of the environment does (the default profile
	 * of Docker), which PRoot can't override but by tracing every
	 * syscall (PROOT_NO_SECCOMP).  */
	if (mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0 && errno == EPERM)
		exit(125);

	snprintf(base, sizeof(base), "%s/test-6b2f0d58-XXXXXX", tmpdir ? tmpdir : "/tmp");
	if (mkdtemp(base) == NULL) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	if (   mkdir(at("", "target"), 0700) < 0 || mkdir(at("", "empty"), 0700) < 0
	    || (fd = creat(at("", "target/marker"), 0600)) < 0 || close(fd) < 0
	    || mkdir(at("", "root"), 0700) < 0 || mkdir(at("", "root/proc"), 0700) < 0
	    || mkdir(at("", "root/old"), 0700) < 0) {
		perror("setup");
		exit(EXIT_FAILURE);
	}

	check_growth(mount_umount, 0);
	check_growth(mount_over, 1);
	CHECK(access(at("", "target/marker"), F_OK) == 0);

	/* As bubblewrap does, in the first tracee: the one the bindings
	 * set at startup belong to.  */
	CHECK(mount(at("", "root"), at("", "root"), NULL, MS_BIND, NULL) == 0);
	CHECK(mount("/proc", at("", "root/proc"), NULL, MS_BIND, NULL) == 0);
	CHECK(syscall(SYS_pivot_root, at("", "root"), at("", "root/old")) == 0);
	CHECK(chdir("/") == 0);
	CHECK(access("/proc/self/status", F_OK) == 0);
	CHECK(access("/old/proc/self/status", F_OK) == 0);
	CHECK(access(at("/old", "target/marker"), F_OK) == 0);
	CHECK(access(at("", "target/marker"), F_OK) < 0);

	/* Clean up, through the previous root.  */
	CHECK(unlink(at("/old", "target/marker")) == 0);
	CHECK(rmdir(at("/old", "target")) == 0);
	CHECK(rmdir(at("/old", "empty")) == 0);
	CHECK(rmdir(at("/old", "root/proc")) == 0);
	CHECK(rmdir(at("/old", "root/old")) == 0);
	CHECK(rmdir(at("/old", "root")) == 0);
	CHECK(rmdir(at("/old", "")) == 0);

	exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
