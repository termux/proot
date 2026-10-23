#include <stdio.h>     /* rename(2), renameat(2), */
#include <stdlib.h>    /* getenv, free, */
#include <fcntl.h>     /* open(2), openat(2), AT_FDCWD, O_*, */
#include <unistd.h>    /* symlink(2), symlinkat(2), readlink(2), lstat(2), unlink(2), unlinkat(2)*/
#include <string.h>    /* str*, strrchr, strcat, strcpy, strncpy, strncmp */
#include <sys/types.h> /* lstat(2), */
#include <sys/stat.h>  /* lstat(2), */
#include <sys/ptrace.h>/* PTRACE_SYSCALL, */
#include <errno.h>     /* E*, */
#include <limits.h>    /* PATH_MAX, */
#include <ctype.h>     /* isdigit, */
#include <stdbool.h>   /* bool, true, false, */
#include <dirent.h>    /* DT_LNK, IFTODT, */
#include <talloc.h>    /* talloc_*, */

#include "cli/note.h"
#include "execve/execve.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/statx.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "path/path.h"
#include "path/f2fs-bug.h"
#include "arch.h"
#include "attribute.h"

#ifdef USERLAND
#define PREFIX ".proot.l2s."
#endif 
#ifndef USERLAND
#define PREFIX ".l2s."
#endif 
#define DELETED_SUFFIX " (deleted)"

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#ifndef IFTODT
#define IFTODT(mode) (((mode) & S_IFMT) >> 12)
#endif

static int decrement_intermediate_count(Tracee *tracee, const char original[PATH_MAX],
					const char intermediate[PATH_MAX]);

/**
 * Configuration of this extension, attached to each tracee.  It only
 * describes the syscall being processed, hence it is never shared with
 * children.
 */
typedef struct {
	/* Host path of the last faked hard link the path being translated
	 * went through, that is, the name the tracee reached a file of the
	 * l2s directory by.  Empty when it went through none.  */
	char dereferenced_link[PATH_MAX];

	/* Host path of the faked hard link the syscall being processed
	 * was redirected away from, when this syscall is about to return
	 * a descriptor on it.  Empty otherwise.  */
	char pending_link[PATH_MAX];

	/* Host path of the faked hard link the syscall being processed
	 * is about to remove -- unlink(2), or rename(2) onto it -- and
	 * the intermediate it points to, c.f. remember_removed_link().
	 * Empty otherwise.  */
	char removed_link[PATH_MAX];
	char removed_intermediate[PATH_MAX];
} Link2SymlinkConfig;

/**
 * Return the configuration of this @extension, allocating it first if
 * @allocate is true.  This function returns NULL if there's none.
 */
static Link2SymlinkConfig *get_config(Extension *extension, bool allocate)
{
	if (extension->config == NULL) {
		if (!allocate)
			return NULL;
		extension->config = talloc_zero(extension, Link2SymlinkConfig);
	}

	return talloc_get_type(extension->config, Link2SymlinkConfig);
}

/**
 * Descriptors that were opened through a faked hard link.  The kernel
 * only knows such a file under the name it was given in the l2s
 * directory -- that's what it reports in "/proc/<PID>/fd/<FD>" -- so
 * these entries remember the name its tracee used instead.  There's no
 * bookkeeping for close(2), dup(2) or fork(2): an entry that doesn't
 * describe anymore the file its descriptor refers to is detected when
 * it is used, then discarded.
 */
#define FD_CACHE_SIZE 64

static struct {
	pid_t pid;
	int fd;
	char *link;
} fd_cache[FD_CACHE_SIZE];
static size_t fd_cache_index;

/**
 * The directory PROOT_L2S_DIR asks the backing files to be kept in,
 * remembered as a descriptor rather than as a name.
 *
 * It has to be a descriptor because the operations below are performed
 * by PRoot itself, with raw host syscalls that no translation applies
 * to: a tracee that replaces the directory with a symbolic link -- it
 * only takes "rm -rf" and "ln -s" on a path it owns, inside its own
 * rootfs, with no concurrency and nothing bound from the host -- has
 * every backing file created outside the rootfs from then on, at a
 * destination of its choosing.  The name is resolved afresh by every
 * one of those syscalls, so checking it beforehand settles nothing;
 * opening it once, O_NOFOLLOW, and naming each entry (descriptor, name)
 * afterwards is what ties the writes to the inode that was checked.
 *
 * The paths recorded *inside* the symbolic links are deliberately left
 * as they were, that is, absolute host paths into this directory: that
 * is what the canonicalization dereferences them through, c.f.
 * detranslate_path().  Only the syscalls change, never the contents.
 *
 * A tracee that re-points the directory afterwards therefore no longer
 * redirects anything; it merely breaks the links of its own rootfs,
 * since the descriptor still names the directory the paths spell out.
 */
static char l2s_directory[PATH_MAX];
static size_t l2s_directory_length;
static int l2s_directory_fd = -1;
static bool l2s_directory_known;

/**
 * Copy PROOT_L2S_DIR into @l2s_directory, without its trailing slashes
 * so that a path can be matched against it by comparison.  This
 * function returns false if no l2s directory is configured, in which
 * case each intermediate is created next to the file it stands for and
 * there is nothing here to protect: that path is canonicalized, hence
 * already confined to the guest rootfs.
 */
static bool get_l2s_directory(void)
{
	const char *value;
	size_t length;

	if (l2s_directory_known)
		return l2s_directory[0] != '\0';

	l2s_directory_known = true;

	value = getenv("PROOT_L2S_DIR");
	if (value == NULL || value[0] == '\0')
		return false;

	length = strlen(value);
	if (length >= PATH_MAX)
		return false;

	while (length > 1 && value[length - 1] == '/')
		length--;

	memcpy(l2s_directory, value, length);
	l2s_directory[length] = '\0';
	l2s_directory_length = length;

	return true;
}

/**
 * Answer a descriptor on the l2s directory, opening it on first use.
 * This function returns -errno if it can't be opened -- O_NOFOLLOW, so
 * a symbolic link left under that name is a refusal and not something
 * to follow.
 */
static int open_l2s_directory(void)
{
	if (l2s_directory_fd >= 0)
		return l2s_directory_fd;

	if (!get_l2s_directory())
		return -ENOENT;

	l2s_directory_fd = open(l2s_directory,
				O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (l2s_directory_fd < 0)
		return errno > 0 ? -errno : -ENOENT;

	return l2s_directory_fd;
}

/**
 * Tell how @path has to be named.  On success *@dir_fd is a descriptor
 * on the l2s directory and *@name is the entry in it, or *@dir_fd is -1
 * and *@name is @path itself when @path doesn't lie directly in that
 * directory -- no l2s directory configured, an intermediate created
 * next to its file, or a chain some older version left elsewhere.
 *
 * This function returns -1 with errno set when @path *is* in the l2s
 * directory but that directory can't be opened.  Falling back to the
 * plain path there would defeat the whole point, since that is exactly
 * the state a tracee arranges when it wants the operation to land
 * somewhere else.
 */
static int l2s_entry(const char *path, int *dir_fd, const char **name)
{
	const char *base;
	int fd;

	*dir_fd = -1;
	*name = path;

	if (!get_l2s_directory())
		return 0;

	if (strncmp(path, l2s_directory, l2s_directory_length) != 0
	    || path[l2s_directory_length] != '/')
		return 0;

	base = path + l2s_directory_length + 1;
	if (base[0] == '\0' || strchr(base, '/') != NULL)
		return 0;

	fd = open_l2s_directory();
	if (fd < 0) {
		errno = -fd;
		return -1;
	}

	*dir_fd = fd;
	*name = base;

	return 0;
}

/**
 * The handful of operations this extension performs on the l2s
 * directory, each naming its entry relative to the descriptor above
 * when that is where it lies.  They keep the return convention of the
 * calls they stand for: 0 or -1 with errno set.
 */
static int l2s_lstat(const char *path, struct stat *statl)
{
	const char *name;
	int dir_fd;

	if (l2s_entry(path, &dir_fd, &name) < 0)
		return -1;

	return (dir_fd < 0) ? lstat(path, statl) : fstatat(dir_fd, name, statl, AT_SYMLINK_NOFOLLOW);
}

static int l2s_symlink(const char *target, const char *path)
{
	const char *name;
	int dir_fd;

	if (l2s_entry(path, &dir_fd, &name) < 0)
		return -1;

	return (dir_fd < 0) ? symlink(target, path) : symlinkat(target, dir_fd, name);
}

static int l2s_unlink(const char *path)
{
	const char *name;
	int dir_fd;

	if (l2s_entry(path, &dir_fd, &name) < 0)
		return -1;

	return (dir_fd < 0) ? unlink(path) : unlinkat(dir_fd, name, 0);
}

static int l2s_rename(const char *old_path, const char *new_path)
{
	const char *old_name;
	const char *new_name;
	int old_dir_fd;
	int new_dir_fd;

	if (l2s_entry(old_path, &old_dir_fd, &old_name) < 0)
		return -1;
	if (l2s_entry(new_path, &new_dir_fd, &new_name) < 0)
		return -1;

	if (old_dir_fd < 0 && new_dir_fd < 0)
		return rename(old_path, new_path);

	/* An absolute path with AT_FDCWD is the side that isn't in the
	 * l2s directory -- the file being moved into it, typically.  */
	return renameat(old_dir_fd < 0 ? AT_FDCWD : old_dir_fd, old_name,
			new_dir_fd < 0 ? AT_FDCWD : new_dir_fd, new_name);
}

/**
 * Copy the contents of the @symlink into @value (nul terminated).
 * This function returns -errno if an error occured, otherwise 0.
 */
static int my_readlink(const char symlink[PATH_MAX], char value[PATH_MAX])
{
	const char *name;
	int dir_fd;
	ssize_t size;

	if (l2s_entry(symlink, &dir_fd, &name) < 0)
		return -errno;

	size = (dir_fd < 0)
		? readlink(symlink, value, PATH_MAX)
		: readlinkat(dir_fd, name, value, PATH_MAX);
	if (size < 0)
		return -errno;
	if (size >= PATH_MAX)
		return -ENAMETOOLONG;
	value[size] = '\0';

	return 0;
}

/**
 * Check whether @sysnum is a syscall that returns a descriptor on the
 * file it is given the path of.
 */
static bool is_open_syscall(Sysnum sysnum)
{
	switch (sysnum) {
	case PR_creat:
	case PR_open:
	case PR_openat:
	case PR_openat2:
		return true;

	default:
		return false;
	}
}

/**
 * The highest link count, c.f. get_link_count().
 */
#define MAX_LINK_COUNT 999999999

/**
 * Return the link count recorded in the name of @host_path, a file this
 * extension has moved into the l2s directory, that is,
 * "<PREFIX><name><NNNN>.<count>" where <NNNN> is the suffix of its
 * intermediate and <count> is written with 4 digits at least -- 5 from
 * 10000 links on -- and 9 at most, so it fits an int.  This function
 * returns -1 if @host_path is not named that way.
 */
static int get_link_count(const char *host_path)
{
	const char *name;
	const char *dot;
	size_t length;
	size_t i;
	int count;

	name = strrchr(host_path, '/');
	if (name == NULL)
		return -1;
	name++;

	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return -1;

	/* Note: PREFIX ends with a dot, hence there's one.  */
	dot = strrchr(name, '.');
	if ((size_t) (dot - name) < strlen(PREFIX) + 4)
		return -1;

	/* Not "dot[-i]": -i is a huge unsigned offset, clang 21 then
	 * assumes dot is NULL, and PRoot crashes.  */
	for (i = 1; i <= 4; i++) {
		if (!isdigit((unsigned char) *(dot - i)))
			return -1;
	}

	length = strlen(dot + 1);
	if (length < 4 || length > 9)
		return -1;

	count = 0;
	for (i = 1; i <= length; i++) {
		if (!isdigit((unsigned char) dot[i]))
			return -1;
		count = count * 10 + (dot[i] - '0');
	}

	return count;
}

/**
 * Check whether @host_path names a file this extension has moved into
 * the l2s directory, c.f. get_link_count().
 */
static bool is_l2s_file(const char *host_path)
{
	return get_link_count(host_path) >= 0;
}

/**
 * Copy in @new_final the name the file @final -- c.f. get_link_count()
 * -- has once its link count is @link_count.  This function returns
 * -errno if an error occured, otherwise 0.
 */
static int name_link_count(const char final[PATH_MAX], int link_count, char new_final[PATH_MAX])
{
	int length;
	int status;

	/* The count is rewritten as a whole, rather than its last 4
	 * characters, since it gains or loses a digit at 10000.  */
	length = strrchr(final, '.') + 1 - final;

	status = snprintf(new_final, PATH_MAX, "%.*s%04d", length, final, link_count);
	if (status < 0 || status >= PATH_MAX)
		return -ENAMETOOLONG;

	return 0;
}

/**
 * Copy in @intermediate the path of the intermediate the faked hard
 * link @link -- a host path -- points to.  This function returns
 * -errno if @link is not a faked hard link, otherwise 0.
 */
static int read_faked_hard_link(const char link[PATH_MAX], char intermediate[PATH_MAX])
{
	const char *name;
	int status;

	status = my_readlink(link, intermediate);
	if (status < 0)
		return status;

	name = strrchr(intermediate, '/');
	if (name == NULL)
		return -EINVAL;
	name++;

	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return -EINVAL;

	return 0;
}

/**
 * Copy in @final the path of the file the faked hard link @link -- a
 * host path -- refers to.  This function returns -errno if @link is
 * not a faked hard link or if it is a broken one, otherwise 0.
 */
static int resolve_faked_hard_link(const char link[PATH_MAX], char final[PATH_MAX])
{
	char intermediate[PATH_MAX];
	int status;

	status = read_faked_hard_link(link, intermediate);
	if (status < 0)
		return status;

	return my_readlink(intermediate, final);
}

/**
 * Copy in @final the path of the file the @intermediate -- a host path
 * -- points to.  This function returns -errno if @intermediate can't be
 * read, -ENOENT if it doesn't point to a file named with a link count,
 * that is, if the chain is broken, otherwise 0.
 */
static int read_intermediate(const char intermediate[PATH_MAX], char final[PATH_MAX])
{
	int status;

	status = my_readlink(intermediate, final);
	if (status < 0)
		return status;

	/* Not a chain this extension made: there is no count to read in
	 * this name, and nothing to rename or to delete on its behalf.  */
	if (!is_l2s_file(final))
		return -ENOENT;

	return 0;
}

/**
 * Copy in @intermediate the path of the intermediate that points to
 * @final, a file this extension has moved into the l2s directory, c.f.
 * get_link_count().  This function returns -errno if there's none,
 * otherwise 0.
 */
static int find_intermediate(const char final[PATH_MAX], char intermediate[PATH_MAX])
{
	char pointee[PATH_MAX];
	struct stat statf;
	struct stat statp;
	size_t length;
	int status;

	/* "<PREFIX><name><NNNN>" lies next to "<PREFIX><name><NNNN>.<count>".  */
	length = strrchr(final, '.') - final;
	memcpy(intermediate, final, length);
	intermediate[length] = '\0';

	status = read_intermediate(intermediate, pointee);
	if (status < 0)
		return status;

	/* The same file, whatever the path spells.  */
	if (stat(final, &statf) < 0 || stat(pointee, &statp) < 0)
		return -errno;
	if (statf.st_dev != statp.st_dev || statf.st_ino != statp.st_ino)
		return -ENOENT;

	return 0;
}

/**
 * Remember that the descriptor @fd of the process @pid was opened
 * through the faked hard link @link (a host path).
 */
static void remember_fd(pid_t pid, int fd, const char link[PATH_MAX])
{
	size_t index;
	size_t slot;
	char *copy;

	/* Reuse the entry of this very descriptor, if any, in order to
	 * not fill the cache with stale duplicates.  */
	slot = FD_CACHE_SIZE;
	for (index = 0; index < FD_CACHE_SIZE; index++) {
		if (fd_cache[index].link != NULL
		    && fd_cache[index].pid == pid
		    && fd_cache[index].fd == fd) {
			slot = index;
			break;
		}
	}

	if (slot == FD_CACHE_SIZE) {
		slot = fd_cache_index;
		fd_cache_index = (fd_cache_index + 1) % FD_CACHE_SIZE;
	}

	/* Note: entries live as long as PRoot does, they are not talloc'ed
	 * from any tracee -- descriptors outlive the process that opened
	 * them, and threads don't share their pid.  */
	copy = strdup(link);
	if (copy == NULL)
		return;

	free(fd_cache[slot].link);
	fd_cache[slot].link = copy;
	fd_cache[slot].pid  = pid;
	fd_cache[slot].fd   = fd;
}

/**
 * Return the faked hard link the descriptor @fd of the process @pid
 * was opened through, or NULL if it is unknown.  Threads share their
 * descriptors but not their pid, so an entry remembered by a sibling
 * is returned as a fallback; the caller is expected to check it still
 * leads to the expected file.
 */
static const char *recall_fd(pid_t pid, int fd)
{
	const char *fallback = NULL;
	size_t index;

	for (index = 0; index < FD_CACHE_SIZE; index++) {
		if (fd_cache[index].link == NULL || fd_cache[index].fd != fd)
			continue;

		if (fd_cache[index].pid == pid)
			return fd_cache[index].link;

		fallback = fd_cache[index].link;
	}

	return fallback;
}

/**
 * Report in @state the name its tracee used to open the file its
 * descriptor refers to, instead of the name this file was given in the
 * l2s directory.
 */
static void readlink_proc_fd(struct readlink_proc_fd_state *state)
{
	char final[PATH_MAX];
	const char *link;

	/* Only files that live in the l2s directory are reported by the
	 * kernel under a name no tracee ever used.  */
	if (!is_l2s_file(state->host_path))
		return;

	link = recall_fd(state->pid, state->fd);
	if (link == NULL)
		return;

	/* Descriptor numbers get reused and links get removed, so ensure
	 * the remembered name still leads to this very file.  */
	if (resolve_faked_hard_link(link, final) < 0)
		return;
	if (strcmp(final, state->host_path) != 0)
		return;

	strcpy(state->host_path, link);
	state->substituted = true;
}

/**
 * Remember @link -- a host path whose content is @referee -- if it is
 * a faked hard link, that is, if it points to the intermediate of a
 * file of the l2s directory.  The canonicalization of a single path
 * can dereference several links before it reaches such a file:
 * ordinary symbolic links first -- "/usr/bin/uname" ->
 * "../lib/cargo/bin/coreutils/uname" on Ubuntu -- then the faked hard
 * link itself, then its intermediate.  The name to report is the one
 * of the faked hard link, just like the kernel reports the name of the
 * real hard link a path leads to, whatever symbolic links were
 * followed before.
 */
static void remember_dereferenced_link(Extension *extension, const char *link, const char *referee)
{
	Link2SymlinkConfig *config;
	const char *link_name;
	const char *name;
	size_t length;
	size_t i;

	name = strrchr(referee, '/');
	name = (name == NULL ? referee : name + 1);

	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return;

	/* Both a faked hard link and its intermediate point to a name
	 * that starts with PREFIX, but only the intermediate points to
	 * its own name followed by the link count: "<name>.<NNNN>", with
	 * more digits from 10000 links on.  */
	link_name = strrchr(link, '/');
	link_name = (link_name == NULL ? link : link_name + 1);
	length = strlen(link_name);

	if (   strlen(name) >= length + 5
	    && strncmp(name, link_name, length) == 0
	    && name[length] == '.') {
		for (i = length + 1; isdigit((unsigned char) name[i]); i++)
			;
		if (name[i] == '\0')
			return;
	}

	config = get_config(extension, true);
	if (config == NULL)
		return;

	strcpy(config->dereferenced_link, link);
}

/**
 * Return the host path of the faked hard link the path being translated
 * went through to reach @host_path -- a file of the l2s directory --, or
 * NULL if there's none.
 */
static const char *l2s_link_to_host_path(Extension *extension, const char host_path[PATH_MAX])
{
	Link2SymlinkConfig *config;
	char final[PATH_MAX];

	if (!is_l2s_file(host_path))
		return NULL;

	config = get_config(extension, false);
	if (config == NULL || config->dereferenced_link[0] == '\0')
		return NULL;

	/* Ensure this link is indeed a faked hard link to this very file:
	 * the tracee may have named the l2s file directly.  */
	if (resolve_faked_hard_link(config->dereferenced_link, final) < 0)
		return NULL;
	if (strcmp(final, host_path) != 0)
		return NULL;

	return config->dereferenced_link;
}

/**
 * Report in @state the faked hard link the program being executed was
 * reached through, rather than the file of the l2s directory PRoot
 * loads.  That link is what the kernel reports in "/proc/<PID>/exe"
 * for a real hard link, and multi-call programs -- the uutils coreutils
 * of Ubuntu -- refuse to run unless its name is the utility they were
 * invoked as.
 */
static void execve_proc_exe(Extension *extension, struct execve_proc_exe_state *state)
{
	const char *link;
	char guest_link[PATH_MAX];
	int status;

	link = l2s_link_to_host_path(extension, state->host_path);
	if (link == NULL)
		return;

	strcpy(guest_link, link);
	status = detranslate_path(TRACEE(extension), guest_link, NULL);
	if (status < 0)
		return;

	strcpy(state->guest_path, guest_link);
	state->substituted = true;
}

/**
 * Make the path @tracee's @link_target_sysarg names a symbolic link to
 * @target, the content of the ordinary symbolic link link(2) is asked to
 * link -- it doesn't follow it.  That link is left where it is: its
 * content is a path of the guest, relative to the directory of the link
 * more often than not, not the host path the files of a faked hard link
 * could be created at.  Both names are then two symbolic links with the
 * same content rather than a single one with a link count of 2; the
 * content of a symbolic link can't be changed, so this only shows in
 * their own metadata -- inode, link count, owner, times.  This function
 * returns -errno if an error occured, otherwise 0.
 */
static int link_symbolic_link(Tracee *tracee, const char target[PATH_MAX], Reg link_target_sysarg)
{
	char link[PATH_MAX];
	int status;

	/* Note: this path was already canonicalized.  */
	status = read_path(tracee, link, peek_reg(tracee, CURRENT, link_target_sysarg));
	if (status < 0)
		return status;

	if (symlink(target, link) < 0)
		return -errno;

	poke_reg(tracee, SYSARG_RESULT, 0);
	set_sysnum(tracee, PR_void);

	return 0;
}

/**
 * Move the path pointed to by @tracee's @sysarg to a new location,
 * symlink the original path to this new one, make @tracee's @sysarg
 * point to the new location.  This function returns -errno if an
 * error occured, otherwise 0.
 */
static int move_and_symlink_path(Tracee *tracee, Reg sysarg, Reg link_target_sysarg)
{
	char original[PATH_MAX];
	char intermediate[PATH_MAX];
	char new_intermediate[PATH_MAX];
	char final[PATH_MAX];
	char new_final[PATH_MAX];
	char * name;
	struct stat statl;
	ssize_t size;
	int status;
	int link_count;
	int first_link = 1;
	int intermediate_suffix = 1;

	/* Note: this path was already canonicalized.  */
	size = read_string(tracee, original, peek_reg(tracee, CURRENT, sysarg), PATH_MAX);
	if (size < 0)
		return size;
	if (size >= PATH_MAX)
		return -ENAMETOOLONG;

	/* Sanity check: directories can't be linked.  */
	status = lstat(original, &statl);
	if (status < 0)
		return errno > 0 ? -errno : -ENOENT;
	if (S_ISDIR(statl.st_mode))
		return -EPERM;

	/* Check if it is a symbolic link.  */
	if (S_ISLNK(statl.st_mode)) {
		/* get name */
		size = my_readlink(original, intermediate);
		if (size < 0)
			return size;

		name = strrchr(intermediate, '/');
		if (name == NULL)
			name = intermediate;
		else
			name++;

		if (strncmp(name, PREFIX, strlen(PREFIX)) == 0)
			first_link = 0;
		else {
			/* An ordinary symbolic link used to be moved as a
			 * file, under the name its content spells, followed
			 * by the suffixes: in the directory of PRoot for a
			 * relative content, and anywhere on the host for an
			 * absolute one, out of the guest rootfs.  */
			return link_symbolic_link(tracee, intermediate, link_target_sysarg);
		}
	} else if (is_l2s_file(original) && find_intermediate(original, intermediate) == 0) {
		/* linkat(AT_SYMLINK_FOLLOW) -- what ln(1) does on Termux
		 * -- is handed the file a faked hard link stands for:
		 * PRoot dereferenced that link like any symbolic link.
		 * It is linked like the faked hard link, through its
		 * intermediate.  It used to be linked as a new file, under
		 * a name made of its own, so the count of the first chain
		 * stayed as it was.  */
		first_link = 0;
	} else {
		/* compute new name */
		name = strrchr(original,'/');
		if (name == NULL)
			name = original;
		else
			name++;

		if (get_l2s_directory()) {
			/* "<l2s>/<PREFIX><name>" plus the four digits of the
			 * suffix and the ".0002" of the final file.  The
			 * bound used to be computed from the *directory* of
			 * @original, which says nothing about the length of
			 * the name appended here: a short directory and a
			 * long name passed it and then overran these
			 * buffers.  */
			if (l2s_directory_length + strlen(PREFIX) + strlen(name) + 11 >= PATH_MAX)
				return -ENAMETOOLONG;

			/* Ask for the descriptor here, so a directory that
			 * can't be opened is reported with the reason it
			 * can't -- ENOTDIR for the symbolic link a tracee
			 * left under that name -- instead of surfacing as
			 * whichever of the operations below fails first.  */
			status = open_l2s_directory();
			if (status < 0)
				return status;

			strcpy(intermediate, l2s_directory);
			strcat(intermediate, "/");
		} else {
			if (strlen(PREFIX) + strlen(original) + 5 >= PATH_MAX)
				return -ENAMETOOLONG;

			strncpy(intermediate, original, strlen(original) - strlen(name));
			intermediate[strlen(original) - strlen(name)] = '\0';
		}
		strcat(intermediate, PREFIX);
		strcat(intermediate, name);
	}

	if (first_link) {
		/* Reserve a free intermediate by creating it, pointing to
		 * the final file the original one is about to become, since
		 * symlink(2) fails on anything in the way.  The slot used to
		 * be told free by access(2), which follows a dangling
		 * intermediate -- that of a broken chain -- so the file was
		 * moved, then left without any name when the intermediate
		 * could not be created.  The final file a broken chain left
		 * behind is not replaced either, and nothing is moved when
		 * there's no free slot left.  The suffix has 4 digits, so
		 * up to 9999 files of the same name can be linked at once:
		 * per directory, or in the whole l2s directory.  */
		for (intermediate_suffix = 1; ; intermediate_suffix++) {
			if (intermediate_suffix > 9999)
				return -EMLINK;

			status = snprintf(final, PATH_MAX, "%s%04d.0002", intermediate, intermediate_suffix);
			if (status < 0 || status >= PATH_MAX)
				return -ENAMETOOLONG;
			sprintf(new_intermediate, "%s%04d", intermediate, intermediate_suffix);

			if (l2s_lstat(final, &statl) == 0)
				continue;

			if (l2s_symlink(final, new_intermediate) == 0)
				break;

			if (errno != EEXIST)
				return -errno;
		}
		strcpy(intermediate, new_intermediate);

		/*Move the original content to the new path. */
		status = l2s_rename(original, final);
		if (status < 0) {
			status = -errno;
			(void) l2s_unlink(intermediate);
			return status;
		}
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) original, (intptr_t) final);

		/* Symlink the original path to the intermediate one.  */
		if (status >= 0 && symlink(intermediate, original) < 0)
			status = -errno;

		/* Otherwise put the file back where it was, unless its name
		 * was taken in the meantime.  */
		if (status < 0) {
			if (status != -EEXIST && l2s_rename(final, original) == 0) {
				(void) notify_extensions(tracee, LINK2SYMLINK_RENAME,
							(intptr_t) final, (intptr_t) original);
				(void) l2s_unlink(intermediate);
			}
			return status;
		}
	} else {
		/*Move the original content to new location, by incrementing count at end of path. */
		status = read_intermediate(intermediate, final);
		if (status < 0)
			return status;

		link_count = get_link_count(final);
		if (link_count >= MAX_LINK_COUNT)
			return -EMLINK;

		status = name_link_count(final, link_count + 1, new_final);
		if (status < 0)
			return status;

		status = l2s_rename(final, new_final);
		if (status < 0)
			return -errno;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final, (intptr_t) new_final);
		if (status < 0)
			return status;
		strcpy(final, new_final);
		/* Symlink the intermediate to the final file.  */
		status = l2s_unlink(intermediate);
		if (status < 0)
			return -errno;
		status = l2s_symlink(final, intermediate);
		if (status < 0)
			return -errno;
	}

	/* Perform symlink() operation within PRoot.  */
	status = read_path(tracee, final, peek_reg(tracee, CURRENT, link_target_sysarg));
	if (status >= 0 && symlink(intermediate, final) < 0)
		status = -errno;
	if (status < 0) {
		(void) decrement_intermediate_count(tracee, original, intermediate);
		return status;
	}
	poke_reg(tracee, SYSARG_RESULT, 0);
	set_sysnum(tracee, PR_void);

	return 0;
}


/**
 * Decrement the count of the file the @intermediate of the faked hard
 * link @original -- both host paths -- points to, deleting both of them
 * when it was the last link.  This function returns -errno if an error
 * occured, otherwise 0.
 */
static int decrement_intermediate_count(Tracee *tracee, const char original[PATH_MAX],
					const char intermediate[PATH_MAX])
{
	char final[PATH_MAX];
	char new_final[PATH_MAX];
	int status;
	int link_count;

	/* Read intermediate link - if this fails then
	 * this link2symlink is broken and we silently
	 * skip as we were removing it anyway.  */
	if (read_intermediate(intermediate, final) < 0) {
		VERBOSE(tracee, 1, "Skiping deref of broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
		return 0;
	}

	link_count = get_link_count(final);
	link_count--;

	/* Check if it is or is not the last link to delete */
	if (link_count > 0) {
		status = name_link_count(final, link_count, new_final);
		if (status < 0)
			return status;

		status = l2s_rename(final, new_final);
		if (status < 0)
			return -errno;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final, (intptr_t) new_final);
		if (status < 0)
			return status;

		strcpy(final, new_final);

		/* Symlink the intermediate to the final file.  */
		status = l2s_unlink(intermediate);
		if (status < 0)
			return -errno;

		status = l2s_symlink(final, intermediate);
		if (status < 0)
			return -errno;
	} else {
		/* If it is the last, delete the intermediate and final */
		status = l2s_unlink(intermediate);
		if (status < 0)
			return -errno;
		status = l2s_unlink(final);
		if (status < 0)
			return -errno;
		status = notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t) final, 0);
		if (status < 0)
			return status;
		}

	return 0;
}

/**
 * Remember the faked hard link @sysarg names, if it is one, as the name
 * the syscall being processed is about to remove.  Its count is
 * decremented by forget_removed_link() once the kernel has actually
 * removed that name: doing it beforehand deleted the data along with
 * the last link even when the syscall then failed, and otherwise left
 * the count one too low -- that is, the data deleted later on while a
 * name of it still existed.  This function returns -errno if an error
 * occured, otherwise 0.
 */
static int remember_removed_link(Extension *extension, Reg sysarg)
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	char link[PATH_MAX];
	char intermediate[PATH_MAX];
	ssize_t size;

	/* Note: this path was already canonicalized.  */
	size = read_string(tracee, link, peek_reg(tracee, CURRENT, sysarg), PATH_MAX);
	if (size < 0)
		return size;
	if (size >= PATH_MAX)
		return -ENAMETOOLONG;

	if (read_faked_hard_link(link, intermediate) < 0)
		return 0;

	config = get_config(extension, true);
	if (config == NULL)
		return -ENOMEM;

	strcpy(config->removed_link, link);
	strcpy(config->removed_intermediate, intermediate);

	return 0;
}

/**
 * Prepare the rename(2) of the path @old_sysarg names to the one
 * @new_sysarg names, with the renameat2(2) @flags.  This function
 * returns -errno if an error occured, otherwise 0.
 */
static int prepare_rename(Extension *extension, Reg old_sysarg, Reg new_sysarg, word_t flags)
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	char old_path[PATH_MAX];
	char old_intermediate[PATH_MAX];
	ssize_t size;
	int status;

	/* Neither of these removes the new name: RENAME_NOREPLACE fails
	 * when it exists, RENAME_EXCHANGE gives it to the old file.  */
	if ((flags & (RENAME_NOREPLACE | RENAME_EXCHANGE)) != 0)
		return 0;

	status = remember_removed_link(extension, new_sysarg);
	if (status < 0)
		return status;

	config = get_config(extension, false);
	if (config == NULL || config->removed_link[0] == '\0')
		return 0;

	/* Note: this path was already canonicalized.  */
	size = read_string(tracee, old_path, peek_reg(tracee, CURRENT, old_sysarg), PATH_MAX);
	if (size < 0)
		return size;
	if (size >= PATH_MAX)
		return -ENAMETOOLONG;

	if (read_faked_hard_link(old_path, old_intermediate) < 0
	    || strcmp(old_intermediate, config->removed_intermediate) != 0)
		return 0;

	/* Both names are links to the same file -- or are the same
	 * name -- in which case rename(2) does nothing.  The kernel
	 * sees two different symbolic links though, and would replace
	 * the new one with the old one, that is, remove the old name.
	 * Have it rename the old name onto itself instead: that is the
	 * very same no-op, behind the very same checks (EROFS, ...).  */
	poke_reg(tracee, new_sysarg, peek_reg(tracee, CURRENT, old_sysarg));
	config->removed_link[0] = '\0';

	return 0;
}

/**
 * Decrement the count of the @intermediate of the faked hard link
 * @link, as decrement_intermediate_count() does, now that the kernel
 * has removed @link.  The directory of @link was writable to do so, but
 * maybe only for the duration of that syscall -- that's how fake_id0
 * grants it, c.f. override_permissions() -- and the directory of
 * @intermediate can be another one.  The count is PRoot's own business
 * though, hence the write permission on the latter is granted for the
 * time being when it's lacking.  This function returns -errno if an
 * error occured, otherwise 0.
 */
static int decrement_removed_link_count(Tracee *tracee, const char link[PATH_MAX],
					const char intermediate[PATH_MAX])
{
	char directory[PATH_MAX];
	struct stat statl;
	char *slash;
	int status;

	status = decrement_intermediate_count(tracee, link, intermediate);
	if (status != -EACCES)
		return status;

	strcpy(directory, intermediate);
	slash = strrchr(directory, '/');
	if (slash == NULL || slash == directory)
		return status;
	*slash = '\0';

	if (stat(directory, &statl) < 0
	    || chmod(directory, (statl.st_mode & 07777) | S_IWUSR) < 0)
		return status;

	status = decrement_intermediate_count(tracee, link, intermediate);

	(void) chmod(directory, statl.st_mode & 07777);

	return status;
}

/**
 * Decrement the count of the faked hard link remembered by
 * remember_removed_link(), now that the syscall being processed has
 * returned, if it did remove that name.
 */
static void forget_removed_link(Extension *extension)
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	char value[PATH_MAX];
	int status;

	config = get_config(extension, false);
	if (config == NULL || config->removed_link[0] == '\0')
		return;

	/* The result is not enough on its own: when the outer seccomp
	 * policy rejects the syscall after its sysenter stop -- under
	 * PROOT_NO_SECCOMP, typically -- this register holds whatever
	 * the kernel rolled back into it, not an error, and the exit
	 * stage of rename(2) even turns that into 0.  The name must be
	 * gone too, or be another file's after rename(2).  */
	if ((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
	    && (my_readlink(config->removed_link, value) < 0
		|| strcmp(value, config->removed_intermediate) != 0)) {
		status = decrement_removed_link_count(tracee, config->removed_link,
						      config->removed_intermediate);
		if (status < 0)
			VERBOSE(tracee, 1, "link2symlink: can't decrement the link count of \"%s\", status=%d",
				config->removed_link, status);
	}

	config->removed_link[0] = '\0';
}

/**
 * Return the d_type of what lstat(2) reports to the tracee for @path --
 * a host path -- if it is a faked hard link, that is, the type of its
 * file, c.f. translated_path().  This function returns -errno if @path
 * is not a faked hard link, or if its file can't be reached.
 */
static int get_faked_hard_link_type(const char path[PATH_MAX])
{
	char final[PATH_MAX];
	struct stat statl;
	int status;

	status = resolve_faked_hard_link(path, final);
	if (status < 0)
		return status;

	/* The paths this extension records are absolute; a relative one
	 * would be resolved against the directory of PRoot.  */
	if (final[0] != '/')
		return -EINVAL;

	if (l2s_lstat(final, &statl) < 0)
		return -errno;

	return IFTODT(statl.st_mode);
}

/**
 * Give the faked hard links listed by the getdents(2) or getdents64(2)
 * @tracee has just performed the type lstat(2) reports for them, instead
 * of DT_LNK, the type of the symbolic links they really are.  Programs
 * that rely on d_type -- "find -type f", ripgrep, Rust's
 * DirEntry::file_type(), Python's DirEntry.is_symlink() -- otherwise see
 * a symbolic link where lstat(2) sees a regular file, then skip it or
 * trip over the contradiction.
 *
 * Intermediates are left alone: they are symbolic links to statx(2),
 * hence to most recent programs, even though the stat(2) family reports
 * them as the file they point to, c.f. handle_sysexit_end().
 *
 * This syscall is never failed: an entry that can't be checked is left
 * as the kernel reported it.
 */
static int handle_getdents_exit(Tracee *tracee)
{
	char directory[PATH_MAX];
	char path[PATH_MAX];
	bool directory_known = false;
	bool dirent64;
	size_t reclen_offset;
	size_t name_offset;
	size_t type_offset;
	size_t first_modified;
	size_t last_modified;
	size_t offset;
	size_t length;
	unsigned short reclen;
	const char *name;
	char *buffer;
	word_t address;
	int status;
	int fd;

	status = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (status <= 0)
		return 0;
	length = status;

	/* The first argument is overwritten by the result on some
	 * architectures, hence ORIGINAL.  */
	fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	address = peek_reg(tracee, ORIGINAL, SYSARG_2);

	dirent64 = (get_sysnum(tracee, ORIGINAL) == PR_getdents64);
	if (dirent64) {
		/* struct linux_dirent64: 64-bit d_ino and d_off whatever
		 * the ABI, d_reclen, d_type, then d_name.  */
		reclen_offset = 16;
		name_offset = 19;
	}
	else {
		/* struct linux_dirent: d_ino and d_off of a word each,
		 * d_reclen, d_name, then d_type in the last byte of the
		 * record.  */
		reclen_offset = 2 * sizeof_word(tracee);
		name_offset = reclen_offset + 2;
	}

	buffer = talloc_size(tracee->ctx, length);
	if (buffer == NULL)
		return 0;

	status = read_data(tracee, buffer, address, length);
	if (status < 0)
		return 0;

	first_modified = length;
	last_modified = 0;

	for (offset = 0; offset + name_offset < length; offset += reclen) {
		memcpy(&reclen, buffer + offset + reclen_offset, sizeof(reclen));

		/* Room for an empty name at least, plus d_type at the end
		 * for struct linux_dirent.  */
		if (reclen < name_offset + 2 || reclen > length - offset)
			break;

		type_offset = (dirent64 ? 18 : reclen - 1u);
		if ((unsigned char) buffer[offset + type_offset] != DT_LNK)
			continue;

		name = buffer + offset + name_offset;
		if (memchr(name, '\0', reclen - name_offset) == NULL)
			break;

		/* Only now that it's needed: most directories hold no
		 * symbolic link at all.  */
		if (!directory_known) {
			status = readlink_proc_pid_fd(tracee->pid, fd, directory);
			if (status < 0 || directory[0] != '/')
				return 0;
			if (strcmp(directory, "/") == 0)
				directory[0] = '\0';
			directory_known = true;
		}

		status = snprintf(path, PATH_MAX, "%s/%s", directory, name);
		if (status < 0 || status >= PATH_MAX)
			continue;

		status = get_faked_hard_link_type(path);
		if (status < 0 || status == DT_LNK)
			continue;

		buffer[offset + type_offset] = status;

		if (first_modified == length)
			first_modified = offset + type_offset;
		last_modified = offset + type_offset;
	}

	if (first_modified == length)
		return 0;

	/* Only the span of the entries that changed: without
	 * process_vm_writev(2), this is written word by word.  */
	(void) write_data(tracee, address + first_modified, buffer + first_modified,
			last_modified - first_modified + 1);

	return 0;
}

/**
 * sizeof(struct stat) cut to contain only fields that are at same addresses
 * regardless of whenever tracee is 32-bit or 64-bit.
 *
 * This allows modification of following fields:
 * - st_dev
 * - st_mode
 * - st_nlink
 * - st_uid
 * - st_gid
 * - st_rdev
 * - st_size
 * - st_blksize
 * - st_blocks
 */
#define SIZEOF_RELEVANT_STRUCT_STAT 72

/**
 * Make it so fake hard links look like real hard link with respect to number of links and inode
 * This function returns -errno if an error occured, otherwise 0.
 */
static int handle_sysexit_end(Extension *extension)
{
	Tracee *tracee = TRACEE(extension);
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);

	#ifdef USERLAND
		if ((get_sysnum(tracee, CURRENT) == PR_fstat) || (get_sysnum(tracee, CURRENT) == PR_fstat64))
			return 0;

		if (((sysnum == PR_fstat) || (sysnum == PR_fstat64)) && (get_sysnum(tracee, CURRENT) == PR_readlinkat))
			return 0;
	#endif

	switch (sysnum) {

	case PR_fstatat64:                 //int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
	case PR_newfstatat:                //int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
	case PR_stat64:                    //int stat(const char *path, struct stat *buf);
	case PR_lstat64:                   //int lstat(const char *path, struct stat *buf);
	case PR_fstat64:                   //int fstat(int fd, struct stat *buf);
	case PR_stat:                      //int stat(const char *path, struct stat *buf);
	case PR_lstat:                     //int lstat(const char *path, struct stat *buf);
	case PR_fstat: {                   //int fstat(int fd, struct stat *buf);
		word_t result;
		Reg sysarg_stat;
		Reg sysarg_path;
		int status;
		struct stat statl = {};
		ssize_t size;
		char original[PATH_MAX];
		char intermediate[PATH_MAX];
		char final[PATH_MAX];
		char * name;
		struct stat finalStat;
		int link_count;

		/* Override only if it succeed.  */
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if (result != 0)
			return 0;

		if (sysnum == PR_fstat64 || sysnum == PR_fstat) {
			#ifndef USERLAND
				status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, MODIFIED, SYSARG_1), original);
				if (status < 0) {
					VERBOSE(tracee, 3, "link2symlink: readlink_proc_pid_fd failed, status=%d", status);
					return 0; // Don't alter syscall result
				}
				if (strlen(original) > strlen(DELETED_SUFFIX) &&
						strcmp(original + strlen(original) - strlen(DELETED_SUFFIX), DELETED_SUFFIX) == 0)
					original[strlen(original) - strlen(DELETED_SUFFIX)] = '\0';
			#endif
			#ifdef USERLAND
				size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_2), PATH_MAX);
				if (size < 0)
					return size;
				if (size >= PATH_MAX)
					return -ENAMETOOLONG;
			#endif
		} else {
			if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
				sysarg_path = SYSARG_2;
			else
				sysarg_path = SYSARG_1;
			size = read_string(tracee, original, peek_reg(tracee, MODIFIED, sysarg_path), PATH_MAX);
			if (size < 0)
				return size;
			if (size >= PATH_MAX)
				return -ENAMETOOLONG;
		}

		name = strrchr(original, '/');
		if (name == NULL)
			name = original;
		else
			name++;

		/* Check if it is a link */
		status = lstat(original, &statl);

		if (strncmp(name, PREFIX, strlen(PREFIX)) == 0) {
			if (S_ISLNK(statl.st_mode)) {
				strcpy(intermediate,original);
				goto intermediate_proc;
			} else {
				strcpy(final,original);
				goto final_proc;
			}
		}

		if (!S_ISLNK(statl.st_mode))
			return 0;

		/* From here on, a faked hard link that can't be followed
		 * down to its file -- whose backing files were removed
		 * along with the directory of its first name, typically --
		 * is left as the kernel reported it, that is, as the
		 * dangling symbolic link it is.  Failing this syscall made it
		 * impossible to lstat(2), hence to list or to remove with
		 * most tools.  */
		if (my_readlink(original, intermediate) < 0)
			return 0;

		name = strrchr(intermediate, '/');
		if (name == NULL)
			name = intermediate;
		else
			name++;

		if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
			return 0;

		intermediate_proc:
		if (read_intermediate(intermediate, final) < 0)
			return 0;

		final_proc:
		link_count = get_link_count(final);
		if (link_count < 0 || lstat(final, &finalStat) < 0)
			return 0;

		finalStat.st_nlink = link_count;

		/* Get the address of the 'stat' structure.  */
		if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
			sysarg_stat = SYSARG_3;
		else
			sysarg_stat = SYSARG_2;

		#ifdef USERLAND
			/* Overwrite the stat struct with the correct number of "links". */
			read_data(tracee, &statl, peek_reg(tracee, ORIGINAL, sysarg_stat), sizeof(statl));
			finalStat.st_mode = statl.st_mode;
			finalStat.st_uid = statl.st_uid;
			finalStat.st_gid = statl.st_gid;
		#endif
		status = write_data(tracee, peek_reg(tracee, ORIGINAL,  sysarg_stat), &finalStat,
			is_32on64_mode(tracee) ? SIZEOF_RELEVANT_STRUCT_STAT : sizeof(finalStat));
		if (status < 0)
			return status;

		return 0;
	}

	case PR_rename:                    //int rename(const char *oldpath, const char *newpath);
	case PR_renameat:                  //int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
	case PR_renameat2:                 //int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
	case PR_unlink:                    //int unlink(const char *pathname);
	case PR_unlinkat:                  //int unlinkat(int dirfd, const char *pathname, int flags);
		forget_removed_link(extension);
		return 0;

	case PR_creat:                     //int creat(const char *pathname, mode_t mode);
	case PR_open:                      //int open(const char *pathname, int flags, ...);
	case PR_openat:                    //int openat(int dirfd, const char *pathname, int flags, ...);
	case PR_openat2: {                 //int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
		Link2SymlinkConfig *config;
		word_t result;

		/* Nothing to do unless this open was redirected to an l2s
		 * file at the enter stage.  */
		config = get_config(extension, false);
		if (config == NULL || config->pending_link[0] == '\0')
			return 0;

		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int) result >= 0)
			remember_fd(tracee->pid, (int) result, config->pending_link);

		config->pending_link[0] = '\0';

		return 0;
	}

	case PR_getdents:                  //int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	case PR_getdents64:                //ssize_t getdents64(int fd, void *dirp, size_t count);
		return handle_getdents_exit(tracee);

	default:
		return 0;
	}
}

static void link2symlink_handle_statx(struct statx_syscall_state *state)
{
	int link_count;

	if (!(state->statx_buf.stx_mask & STATX_NLINK))
		return;

	link_count = get_link_count(state->host_path);
	if (link_count < 0)
		return;

	state->statx_buf.stx_nlink = link_count;

	/* The statx() that PRoot let the kernel perform did succeed, so
	 * its result was read back from the tracee and is not written
	 * again unless it is explicitly reported as updated.  */
	state->updated_stats = true;
}

/**
 * Remember the name the tracee of @extension used for the file it is
 * about to open, when @host_path -- the path this open was redirected
 * to -- is a file of the l2s directory.
 * The kernel knows nothing about faked hard links, so it would report
 * @host_path in "/proc/<PID>/fd/<FD>", c.f. readlink_proc_fd().
 */
static void remember_opened_link(Extension *extension, const char host_path[PATH_MAX])
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	const char *link;

	link = l2s_link_to_host_path(extension, host_path);
	if (link == NULL)
		return;

	config = get_config(extension, false);
	strcpy(config->pending_link, link);

	/* The descriptor number is only known at the exit stage, which
	 * seccomp lets PRoot skip by default.  */
	tracee->sysexit_pending = true;
	tracee->restart_how = PTRACE_SYSCALL;
}

/**
 * When @translated_path is a faked hard-link, replace it with the
 * point it (internally) points to.
 */
static void translated_path(Extension *extension, char translated_path[PATH_MAX])
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	char final[PATH_MAX];

	/* Don't translate l2s symlinks if call is (un)link */
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
	if (   sysnum == PR_unlink
	    || sysnum == PR_unlinkat
	    || sysnum == PR_link
	    || sysnum == PR_linkat
	    || sysnum == PR_rename
	    || sysnum == PR_renameat
	    || sysnum == PR_renameat2) {
		return;
	}

	if (should_skip_file_access_due_to_f2fs_bug(tracee, translated_path))
		return;

	/* The canonicalization dereferenced the faked hard links this
	 * path was made of, except its last component when it was asked
	 * not to -- lstat(2), open(O_NOFOLLOW), ... -- in which case
	 * that is done here.  The name of that link is remembered the
	 * same way, a faked hard link is a regular file to the tracee.  */
	if (resolve_faked_hard_link(translated_path, final) == 0) {
		config = get_config(extension, true);
		if (config != NULL)
			strcpy(config->dereferenced_link, translated_path);

		strcpy(translated_path, final);
	}

	if (is_open_syscall(sysnum))
		remember_opened_link(extension, translated_path);
}

/**
 * Handler for linkat(..., "/proc/X/fd/Y", ..., AT_SYMLINK_FOLLOW)
 *
 * Returns:
 *    1 if operation was handled successfully
 *      (Syscall should be marked as successful without further actions)
 *    0 if this wasn't linkat from /proc//fd
 *      (Caller should proceed with usual link2symlink)
 *   <0 if operation failed
 *      (Syscall should be marked as failed without further actions)
 */
static int handle_linkat_from_proc_fd(Tracee *tracee) {
	/* Read source path, return if it doesn't belong to /proc  */
	char proc_path[128];
	ssize_t size = read_string(tracee, proc_path, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(proc_path));
	if (size <= 0 || size >= (ssize_t) sizeof(proc_path)) {
		return 0;
	}
	if (compare_paths(proc_path, "/proc") != PATH2_IS_PREFIX) {
		return 0;
	}

	/* Ensure provided path is symlink to " (deleted)" file  */
	char target_path[PATH_MAX] = {};
	int status = readlink(proc_path, target_path, sizeof(target_path));
	if (status < 10 || status >= (ssize_t) sizeof(target_path)) {
		return 0;
	}
	if (0 != memcmp(&target_path[status - 10], DELETED_SUFFIX, 10)) {
		return 0;
	}

	/* Read stats of source file, ensure it is regular file  */
	struct stat stats = {};
	if (0 != stat(proc_path, &stats)) {
		return 0;
	}
	if (!S_ISREG(stats.st_mode)) {
		return 0;
	}

	/* Read path of target file (already translated by proot)  */
	size = read_string(tracee, target_path, peek_reg(tracee, CURRENT, SYSARG_4), PATH_MAX);
	if (size < 0 || size >= (ssize_t) sizeof(target_path)) {
		return 0;
	}

	/* Open source file for reading  */
	int source_fd = open(proc_path, O_RDONLY);
	if (source_fd < 0) {
		return 0;
	}

	/* Point of no return, below we no longer are allowed to "return 0",
	 * any errors will be propagated to caller
	 *
	 * Delete target file (we'll be replacing it).
	 * Ignore result of unlink, file could or could not exist,
	 * we'll report failure of open though  */
	unlink(target_path);

	/* Open target file for writing  */
	int target_fd = open(target_path, O_WRONLY|O_CREAT|O_EXCL, stats.st_mode & 0777);
	if (target_fd < 0) {
		status = -errno;
		if (status >= 0)
			status = -EPERM;
		close(source_fd);
		return status;
	}

	/* Copy contents of file  */
	char buf[4096];
	int nread;
	while (0 != (nread = read(source_fd, buf, sizeof(buf)))) {
		if (nread < 0) {
			status = -errno;
			if (status >= 0)
				status = -EPERM;
			close(source_fd);
			close(target_fd);
			return status;
		}
		int pos = 0;
		while (pos < nread) {
			int nwrite = write(target_fd, buf + pos, nread - pos);
			if (nwrite <= 0) {
				status = -errno;
				if (status >= 0)
					status = -EPERM;
				close(source_fd);
				close(target_fd);
				return status;
			}
			pos += nwrite;
		}
	}

	/* Copy successful, nothing more to be done for this syscall  */
	close(source_fd);
	close(target_fd);
	return 1;
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int link2symlink_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2 UNUSED)
{
	int status;

	switch (event) {
	case INITIALIZATION: {
		/* List of syscalls handled by this extensions.  */
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_link,		FILTER_SYSEXIT },
			{ PR_linkat,		FILTER_SYSEXIT },
			{ PR_unlink,		FILTER_SYSEXIT },
			{ PR_unlinkat,		FILTER_SYSEXIT },
			{ PR_fstat,		FILTER_SYSEXIT },
			{ PR_fstat64,		FILTER_SYSEXIT },
			{ PR_fstatat64,		FILTER_SYSEXIT },
			{ PR_lstat,		FILTER_SYSEXIT },
			{ PR_lstat64,		FILTER_SYSEXIT },
			{ PR_newfstatat,	FILTER_SYSEXIT },
			{ PR_stat,		FILTER_SYSEXIT },
			{ PR_stat64,		FILTER_SYSEXIT },
			{ PR_rename,		FILTER_SYSEXIT },
			{ PR_renameat,		FILTER_SYSEXIT },
			{ PR_renameat2,		FILTER_SYSEXIT },
			{ PR_getdents,		FILTER_SYSEXIT },
			{ PR_getdents64,	FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case SYSCALL_ENTER_START: {
		/* Forget any dereference that was not consumed by the exit
		 * stage of the syscall it was made for.  */
		Link2SymlinkConfig *config = get_config(extension, false);
		if (config != NULL) {
			config->pending_link[0] = '\0';
			config->removed_link[0] = '\0';
		}

		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);

		/* Nothing to do if this syscall is being discarded
		 * because its translation failed: its paths are not all
		 * translated then, and an untranslated one names a file
		 * of the host, out of the guest rootfs.  */
		if ((int) data1 < 0)
			return 0;

		switch (get_sysnum(tracee, ORIGINAL)) {
		case PR_rename:
			/*int rename(const char *oldpath, const char *newpath);
			 *If newpath is a psuedo hard link decrement the link count
			 *once it is replaced, c.f. prepare_rename().
			 */

			status = prepare_rename(extension, SYSARG_1, SYSARG_2, 0);
			if (status < 0)
				return status;

			break;

		case PR_renameat:
		case PR_renameat2:
			/*int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
			 *int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
			 *If newpath is a psuedo hard link decrement the link count
			 *once it is replaced, c.f. prepare_rename().
			 */

			status = prepare_rename(extension, SYSARG_2, SYSARG_4,
					get_sysnum(tracee, ORIGINAL) == PR_renameat2
					? peek_reg(tracee, CURRENT, SYSARG_5) : 0);
			if (status < 0)
				return status;

			break;

		case PR_unlink:
			/* If path points a file that is an symlink to a file that begins
			 *   with PREFIX, let the file be deleted, but also decrement the
			 *   hard link count, if it is greater than 1, otherwise delete
			 *   the original file and intermediate file too -- once the
			 *   file is deleted, c.f. remember_removed_link().
			 */

			status = remember_removed_link(extension, SYSARG_1);
			if (status < 0)
				return status;

			break;

		case PR_unlinkat:
			/* If this is request to delete directory, don't handle it here.
			 * directories cannot be hard links.  */
			if ((peek_reg(tracee, CURRENT, SYSARG_3) & AT_REMOVEDIR) != 0)
			{
				return 0;
			}

			/* If path points a file that is a symlink to a file that begins
			 *   with PREFIX, let the file be deleted, but also delete the
			 *   symlink that was created and decremnt the count that is tacked
			 *   to end of original file -- once the file is deleted, c.f.
			 *   remember_removed_link().
			 */

			status = remember_removed_link(extension, SYSARG_2);
			if (status < 0)
				return status;

			break;

		case PR_link:
			/* Convert:
			 *
			 *     int link(const char *oldpath, const char *newpath);
			 *
			 * into:
			 *
			 *     int symlink(const char *oldpath, const char *newpath);
			 */

			status = move_and_symlink_path(tracee, SYSARG_1, SYSARG_2);
			if (status < 0)
				return status;

			break;

		case PR_linkat:
			/*
			 * Handle linkat(..., "/proc/X/fd/Y", ..., AT_SYMLINK_FOLLOW)
			 */
			if (peek_reg(tracee, CURRENT, SYSARG_5) & AT_SYMLINK_FOLLOW) {
				status = handle_linkat_from_proc_fd(tracee);
				if (status < 0)
					return status;
				if (status == 1) {
					set_sysnum(tracee, PR_void);
					poke_reg(tracee, SYSARG_RESULT, 0);
					return 0;
				}
			}

			/* Convert:
			 *
			 *     int linkat(int olddirfd, const char *oldpath,
			 *                int newdirfd, const char *newpath, int flags);
			 *
			 * into:
			 *
			 *     int symlink(const char *oldpath, const char *newpath);
			 *
			 * Note: PRoot has already canonicalized
			 * linkat() paths this way:
			 *
			 *   olddirfd + oldpath -> oldpath
			 *   newdirfd + newpath -> newpath
			 */

			status = move_and_symlink_path(tracee, SYSARG_2, SYSARG_4);
			if (status < 0)
				return status;

			break;

		default:
			break;
		}
		return 0;
	}

	case SYSCALL_EXIT_END: {
		return handle_sysexit_end(extension);
	}

	case SYSCALL_CHAINED_EXIT: {
		Tracee *tracee = TRACEE(extension);
		word_t sysnum = get_sysnum(tracee, ORIGINAL);
		word_t chained_sysnum = get_sysnum(tracee, CURRENT);

		/* hidden_files reissues getdents(2), with the same
		 * arguments, when it hid every entry it returned.  */
		if ((sysnum == PR_getdents || sysnum == PR_getdents64) && chained_sysnum == sysnum)
			return handle_getdents_exit(tracee);

#ifdef USERLAND
		/* fake_id0 emulates fstat(2) with a readlinkat(2) of
		 * /proc/<pid>/fd/<fd> and a chained fstatat(2) of its
		 * target.  */
		if ((sysnum == PR_fstat || sysnum == PR_fstat64)
		    && (chained_sysnum == PR_fstatat64 || chained_sysnum == PR_newfstatat))
			return handle_sysexit_end(extension);
#endif
		return 0;
	}

	case GUEST_PATH: {
		/* A new path is about to be canonicalized.  */
		Link2SymlinkConfig *config = get_config(extension, false);
		if (config != NULL)
			config->dereferenced_link[0] = '\0';

		return 0;
	}

	case SYMLINK_DEREFERENCED:
		remember_dereferenced_link(extension, (const char *) data1, (const char *) data2);
		return 0;

	case TRANSLATED_PATH:
		translated_path(extension, (char *) data1);
		return 0;

	case STATX_SYSCALL:
		link2symlink_handle_statx((struct statx_syscall_state *) data1);
		return 0;

	case READLINK_PROC_FD:
		readlink_proc_fd((struct readlink_proc_fd_state *) data1);
		return 0;

	case EXECVE_PROC_EXE:
		execve_proc_exe(extension, (struct execve_proc_exe_state *) data1);
		return 0;

	case INHERIT_PARENT:
		/* The configuration only describes the syscall being
		 * processed, hence it can't be shared with the child.  */
		return 1;

	case INHERIT_CHILD:
		/* Nothing to inherit: the child's configuration is
		 * allocated when it is needed.  */
		return 0;

	default:
		return 0;
	}
}
