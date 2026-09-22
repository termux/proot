#include <stdio.h>     /* rename(2), renameat(2), */
#include <stdlib.h>    /* atoi */
#include <fcntl.h>     /* open(2), openat(2), AT_FDCWD, O_*, */
#include <stdbool.h>   /* bool, */
#include <unistd.h>    /* symlink(2), symlinkat(2), readlink(2), lstat(2), unlink(2), unlinkat(2)*/
#include <string.h>    /* str*, strrchr, strcat, strcpy, strncpy, strncmp */
#include <sys/types.h> /* lstat(2), */
#include <sys/stat.h>  /* lstat(2), */
#include <sys/ptrace.h>/* PTRACE_SYSCALL, */
#include <errno.h>     /* E*, */
#include <fcntl.h>     /* AT_FDCWD, */
#include <limits.h>    /* PATH_MAX, */
#include <ctype.h>     /* isdigit, */
#include <stdbool.h>   /* bool, true, false, */
#include <talloc.h>    /* talloc_*, */

#include "cli/note.h"
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

static int decrement_link_count(Tracee *tracee, Reg sysarg);
static int l2s_content_to_host(Tracee *tracee, const char content[PATH_MAX], char host[PATH_MAX]);

/**
 * Configuration of this extension, attached to each tracee.  It only
 * describes the syscall being processed, hence it is never shared with
 * children.
 */
typedef struct {
	/* Host path of the last component of the path being translated,
	 * as it was named before being dereferenced.  Empty when the
	 * canonicalization did not reach it yet.  */
	char final_component[PATH_MAX];

	/* Host path of the faked hard link the syscall being processed
	 * was redirected away from, when this syscall is about to return
	 * a descriptor on it.  Empty otherwise.  */
	char pending_link[PATH_MAX];
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
static char l2s_dir_host[PATH_MAX];
static size_t l2s_dir_host_length;
static int l2s_directory_fd = -1;
static bool l2s_directory_known;
static bool l2s_dir_host_known;

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
 * Whether @path names something directly inside @dir -- @length chars
 * of @dir spelled out, then a slash.  (A deeper remainder is left to
 * the caller to treat as outside the directory.)
 */
static bool l2s_path_in(const char *path, const char *dir, size_t length)
{
	return strncmp(path, dir, length) == 0 && path[length] == '/';
}

/**
 * Host form of the configured l2s directory: a legacy host-path value
 * is used as-is, while a guest-path value -- the recommended form,
 * since stub content must be derefable by the in-guest canonicalizer,
 * c.f. l2s_content_to_host -- is translated to its host path.  The
 * result is cached for the life of the process once resolved.  This
 * function returns NULL when no l2s directory is configured or the
 * guest-path form can't be resolved; a resolution failure is not
 * cached, so a caller may retry once the tracee is further along.
 */
static const char *l2s_host_directory(Tracee *tracee)
{
	struct stat dirst;

	if (l2s_dir_host_known)
		return l2s_dir_host[0] != '\0' ? l2s_dir_host : NULL;

	if (!get_l2s_directory())
		return NULL;

	if (lstat(l2s_directory, &dirst) == 0 && S_ISDIR(dirst.st_mode))
		strcpy(l2s_dir_host, l2s_directory);
	else {
		if (tracee == NULL)
			return NULL;
		if (translate_path(tracee, l2s_dir_host, AT_FDCWD,
				   l2s_directory, true) < 0)
			return NULL;
	}

	l2s_dir_host_length = strlen(l2s_dir_host);
	l2s_dir_host_known = true;

	return l2s_dir_host;
}

/**
 * Answer a descriptor on the l2s directory, opening it on first use.
 * The directory is opened through its host form (see
 * l2s_host_directory).  This function returns -errno if it can't be
 * opened -- O_NOFOLLOW, so a symbolic link left under that name is a
 * refusal and not something to follow.
 */
static int open_l2s_directory(Tracee *tracee)
{
	const char *host;

	if (l2s_directory_fd >= 0)
		return l2s_directory_fd;

	host = l2s_host_directory(tracee);
	if (host == NULL)
		return -ENOENT;

	l2s_directory_fd = open(host,
				O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (l2s_directory_fd < 0)
		return errno > 0 ? -errno : -ENOENT;

	return l2s_directory_fd;
}

/**
 * Tell how @path has to be named.  On success *@dir_fd is a descriptor
 * on the l2s directory and *@name is the entry in it, or *@dir_fd is -1
 * and *@name is @path itself when @path doesn't lie directly in that
 * directory -- no descriptor open yet, an intermediate created next to
 * its file, or a chain some older version left elsewhere.  Only the
 * syscall handlers establish the descriptor (c.f. open_l2s_directory),
 * so a caller that needs it open must call that one first; falling
 * back to the plain path here is what reads and canonicalization want,
 * since neither may resolve anything (see the comment in the body).
 */
static int l2s_entry(Tracee *tracee, const char *path, int *dir_fd, const char **name)
{
	const char *base;
	size_t length;

	(void) tracee;

	*dir_fd = -1;
	*name = path;

	/* Nothing is resolved here: the host form and the descriptor are
	 * established by the syscall handlers (c.f. open_l2s_directory).
	 * Computing them inside a canonicalization callback would call
	 * translate_path() from within translate_path(), which recurses
	 * until the stack is gone.  Until then, a matching path falls
	 * back to the plain syscall, which is what reads need anyway.  */
	if (l2s_directory_fd < 0)
		return 0;

	/* Entries are named either in the host form -- syscalls on the
	 * payload -- or in the content form, the string written into a
	 * symbolic link; match whichever spelling @path uses.  */
	if (l2s_path_in(path, l2s_directory, l2s_directory_length))
		length = l2s_directory_length;
	else if (l2s_dir_host_known
		 && l2s_path_in(path, l2s_dir_host, l2s_dir_host_length))
		length = l2s_dir_host_length;
	else
		return 0;

	base = path + length + 1;
	if (base[0] == '\0' || strchr(base, '/') != NULL)
		return 0;

	*dir_fd = l2s_directory_fd;
	*name = base;

	return 0;
}

/**
 * The handful of operations this extension performs on the l2s
 * directory, each naming its entry relative to the descriptor above
 * when that is where it lies.  They keep the return convention of the
 * calls they stand for: 0 or -1 with errno set.
 */
static int l2s_symlink(Tracee *tracee, const char *target, const char *path)
{
	const char *name;
	int dir_fd;

	if (l2s_entry(tracee, path, &dir_fd, &name) < 0)
		return -1;

	return (dir_fd < 0) ? symlink(target, path) : symlinkat(target, dir_fd, name);
}

static int l2s_unlink(Tracee *tracee, const char *path)
{
	const char *name;
	int dir_fd;

	if (l2s_entry(tracee, path, &dir_fd, &name) < 0)
		return -1;

	return (dir_fd < 0) ? unlink(path) : unlinkat(dir_fd, name, 0);
}

static int l2s_rename(Tracee *tracee, const char *old_path, const char *new_path)
{
	const char *old_name;
	const char *new_name;
	int old_dir_fd;
	int new_dir_fd;

	if (l2s_entry(tracee, old_path, &old_dir_fd, &old_name) < 0)
		return -1;
	if (l2s_entry(tracee, new_path, &new_dir_fd, &new_name) < 0)
		return -1;

	if (old_dir_fd < 0 && new_dir_fd < 0)
		return rename(old_path, new_path);

	/* An absolute path with AT_FDCWD is the side that isn't in the
	 * l2s directory -- the file being moved into it, typically.  */
	return renameat(old_dir_fd < 0 ? AT_FDCWD : old_dir_fd, old_name,
			new_dir_fd < 0 ? AT_FDCWD : new_dir_fd, new_name);
}

/**
 * -errno for a failed libc call.  Guaranteed negative even if errno
 * was left at 0: a negative extension status is poked verbatim into
 * the guest's result register, so returning a raw -1 surfaces as
 * EPERM ("Operation not permitted") for *every* failure — the exact
 * misleading signature of GlassHaven/Haven#324.
 */
static int host_errno(void)
{
	return errno > 0 ? -errno : -EPERM;
}

/**
 * Whether a real link(2) failure means "hard links unavailable here"
 * (fall back to symlink emulation) as opposed to a real answer the
 * guest must see (EEXIST, ENOENT, ENOSPC, ...).
 */
static bool link_errno_means_unsupported(int err)
{
	return (err == EPERM || err == EACCES || err == EXDEV ||
	        err == EMLINK || err == EOPNOTSUPP || err == ENOSYS ||
	        err == EROFS);
}

/**
 * PROOT_L2S_FORCE override, read once: 1 = always emulate (skip the
 * real-hard-link fast path; keeps tests deterministic on hosts where
 * link(2) succeeds), 0 or unset = try a real hard link first.  The
 * fast path itself is attempted per call — EXDEV/EMLINK are per-path
 * properties, so a global negative cache would let one /sdcard
 * attempt permanently degrade linking on the rootfs.
 */
static int l2s_force_mode(void)
{
	static int mode = -2;
	if (mode == -2) {
		const char *env = getenv("PROOT_L2S_FORCE");
		mode = (env == NULL || env[0] == '\0') ? -1 : (env[0] == '1' ? 1 : 0);
	}
	return mode;
}

/**
 * Copy the contents of the @symlink into @value (nul terminated).
 * This function returns -errno if an error occured, otherwise 0.
 */
static int my_readlink(Tracee *tracee, const char symlink[PATH_MAX], char value[PATH_MAX])
{
	const char *name;
	int dir_fd;
	ssize_t size;

	if (l2s_entry(tracee, symlink, &dir_fd, &name) < 0)
		return -errno;

	size = (dir_fd < 0)
		? readlink(symlink, value, PATH_MAX)
		: readlinkat(dir_fd, name, value, PATH_MAX);
	if (size < 0)
		return errno > 0 ? -errno : -EINVAL;
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
 * Check whether @host_path names a file this extension has moved into
 * the l2s directory, that is, "<PREFIX><name><NNNN>.<NNNN>".
 */
static bool is_l2s_file(const char *host_path)
{
	const char *name;
	size_t length;
	size_t i;

	name = strrchr(host_path, '/');
	if (name == NULL)
		return false;
	name++;

	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return false;

	/* 5 = strlen(".0002")  */
	length = strlen(name);
	if (length < strlen(PREFIX) + 5)
		return false;

	if (name[length - 5] != '.')
		return false;

	for (i = 1; i <= 4; i++) {
		if (!isdigit(name[length - i]))
			return false;
	}

	return true;
}

/**
 * Copy in @final the path of the file the faked hard link @link -- a
 * host path -- refers to.  This function returns -errno if @link is
 * not a faked hard link or if it is a broken one, otherwise 0.
 */
static int resolve_faked_hard_link(Tracee *tracee, const char link[PATH_MAX], char final[PATH_MAX])
{
	char intermediate[PATH_MAX];
	const char *name;
	int status;

	status = my_readlink(tracee, link, intermediate);
	if (status < 0)
		return status;

	name = strrchr(intermediate, '/');
	if (name == NULL)
		return -EINVAL;
	name++;

	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return -EINVAL;

	return my_readlink(tracee, intermediate, final);
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
static void readlink_proc_fd(Tracee *tracee, struct readlink_proc_fd_state *state)
{
	char final[PATH_MAX];
	char final_host[PATH_MAX];
	const char *link;

	/* Only files that live in the l2s directory are reported by the
	 * kernel under a name no tracee ever used.  */
	if (!is_l2s_file(state->host_path))
		return;

	link = recall_fd(state->pid, state->fd);
	if (link == NULL)
		return;

	/* Descriptor numbers get reused and links get removed, so ensure
	 * the remembered name still leads to this very file.  Chain
	 * content is compared in its host form, since it may be stored
	 * guest-form (c.f. l2s_content_to_host).  */
	if (resolve_faked_hard_link(tracee, link, final) < 0)
		return;
	if (l2s_content_to_host(tracee, final, final_host) < 0)
		return;
	if (strcmp(final_host, state->host_path) != 0)
		return;

	strcpy(state->host_path, link);
	state->substituted = true;
}

/**
 * Resolve an l2s chain symlink's @content string to a HOST path in
 * @host.  Legacy chains store host-absolute content; guest-content
 * chains (PROOT_L2S_DIR given as a guest path) store guest-absolute
 * content.  Guest content is what makes stubs *readable from inside
 * the guest*: the canonicalizer dereferences symlink content in the
 * guest namespace, and host-absolute content does not reliably
 * detranslate there (observed on Android: every open() through such a
 * stub fails ENOENT while the extension's own host-side walks
 * succeed).  Try the string as a host path first (legacy chains keep
 * working), then translate it as a guest path.
 */
static int l2s_content_to_host(Tracee *tracee, const char content[PATH_MAX], char host[PATH_MAX])
{
	struct stat st;

	if (content[0] == '/' && lstat(content, &st) == 0) {
		strcpy(host, content);
		return 0;
	}
	if (tracee == NULL)
		return -ENOENT;
	return translate_path(tracee, host, AT_FDCWD, content, false);
}

/**
 * Rewrite the 4-digit refcount suffix at the end of @s to @count.
 * @s must already end in 4 digits (callers guard with strlen checks).
 */
static void l2s_set_suffix(char *s, int count)
{
	sprintf(s + strlen(s) - 4, "%04d", count);
}

/**
 * Fill @base with the default (sibling) intermediate base for
 * @original: "<dirname(original)>/<PREFIX><name>".  @name must point
 * at the basename inside @original.  Returns 0 or -ENAMETOOLONG.
 */
static int l2s_sibling_base(const char *original, const char *name, char base[PATH_MAX])
{
	if (strlen(PREFIX) + strlen(original) + 5 >= PATH_MAX)
		return -ENAMETOOLONG;

	strncpy(base, original, strlen(original) - strlen(name));
	base[strlen(original) - strlen(name)] = '\0';
	strcat(base, PREFIX);
	strcat(base, name);
	return 0;
}

/**
 * Reserve a free "<base>NNNN" name and move @original's payload to
 * "<reserved>.0002".  The reservation is the intermediate symlink
 * itself: symlink(2) fails EEXIST atomically on any existing entry —
 * including a *dangling* one, which the old access(F_OK) scan wrongly
 * reported as free (and two proot instances could reserve the same
 * name).  Chain names are carried in two parallel forms: the *content*
 * form written into symlink targets (guest-absolute for PROOT_L2S_DIR
 * chains, so the guest canonicalizer can deref them) and the *host*
 * form used for the extension's own syscalls; for sibling chains the
 * two are identical.  On success fills all four outputs and returns 0;
 * on failure returns -errno with the reservation released.
 */
static int l2s_reserve_and_move(Tracee *tracee, const char *original,
                                const char base_content[PATH_MAX],
                                const char base_host[PATH_MAX],
                                char intermediate_content[PATH_MAX],
                                char intermediate_host[PATH_MAX],
                                char final_content[PATH_MAX],
                                char final_host[PATH_MAX])
{
	int suffix = 1;
	int status;

	for (;;) {
		if (suffix >= 1000)
			return -EMLINK;
		status = snprintf(intermediate_content, PATH_MAX, "%s%04d", base_content, suffix);
		if (status < 0 || status >= PATH_MAX)
			return -ENAMETOOLONG;
		status = snprintf(intermediate_host, PATH_MAX, "%s%04d", base_host, suffix);
		if (status < 0 || status >= PATH_MAX)
			return -ENAMETOOLONG;
		status = snprintf(final_content, PATH_MAX, "%s.0002", intermediate_content);
		if (status < 0 || status >= PATH_MAX)
			return -ENAMETOOLONG;
		status = snprintf(final_host, PATH_MAX, "%s.0002", intermediate_host);
		if (status < 0 || status >= PATH_MAX)
			return -ENAMETOOLONG;
		if (l2s_symlink(tracee, final_content, intermediate_host) == 0)
			break;
		if (errno != EEXIST)
			return host_errno();
		suffix++;
	}

	status = l2s_rename(tracee, original, final_host);
	if (status < 0) {
		status = host_errno();
		l2s_unlink(tracee, intermediate_host);	/* release the reservation */
		return status;
	}

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
	char intermediate_host[PATH_MAX];
	char new_intermediate[PATH_MAX];
	char base_host[PATH_MAX];
	char final[PATH_MAX];
	char final_host[PATH_MAX];
	char new_final[PATH_MAX];
	char new_final_host[PATH_MAX];
	char newpath[PATH_MAX];
	char * name;
	struct stat statl;
	ssize_t size;
	int status;
	int link_count;
	int first_link = 1;

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

	/* Try a real hard link first — but only for a regular-file source,
	 * *after* classification: hard-linking an l2s stub would create a
	 * referent the chain's refcount never learns about.  On a filesystem
	 * that supports hard links (ext4/f2fs — the norm for Android
	 * app-private storage, where the rootfs lives) this is exactly what
	 * an unwrapped Linux system does, and it keeps true hard-link
	 * semantics.  The symlink emulation diverges from real hard links
	 * and breaks tools that link a file to a backup copy — e.g. dpkg
	 * linking a DB file to its "-old" backup (GlassHaven/Haven#324,
	 * #328).  Fall back to emulation only when errno says "hard links
	 * unavailable here"; real answers (EEXIST, ENOENT, ENOSPC, ...) go
	 * back to the guest.  */
	if (!S_ISLNK(statl.st_mode) && l2s_force_mode() != 1) {
		size = read_string(tracee, newpath, peek_reg(tracee, CURRENT, link_target_sysarg), PATH_MAX);
		if (size < 0)
			return size;
		if (size >= PATH_MAX)
			return -ENAMETOOLONG;
		if (link(original, newpath) == 0) {
			poke_reg(tracee, SYSARG_RESULT, 0);
			set_sysnum(tracee, PR_void);
			return 0;
		}
		if (!link_errno_means_unsupported(errno))
			return host_errno();
		/* else fall through to the emulation */
	}

	/* Check if it is a symbolic link.  */
	if (S_ISLNK(statl.st_mode)) {
		/* get name */
		size = my_readlink(tracee, original, intermediate);
		if (size < 0)
			return size;

		name = strrchr(intermediate, '/');
		if (name == NULL)
			name = intermediate;
		else
			name++;

		if (strncmp(name, PREFIX, strlen(PREFIX)) == 0)
			first_link = 0;
		else
			/* Plain-symlink source (legacy oddity): the readlink
			 * target doubles as the intermediate base in both
			 * forms.  */
			strcpy(intermediate_host, intermediate);
	} else {
		/* compute new name */
		name = strrchr(original,'/');
		if (name == NULL)
			name = original;
		else
			name++;

		if (get_l2s_directory()) {
			const char *host = l2s_host_directory(tracee);
			if (host == NULL)
				return -ENOENT;

			/* "<l2s>/<PREFIX><name>" plus the four digits of the
			 * suffix and the ".0002" of the final file.  The
			 * bound used to be computed from the *directory* of
			 * @original, which says nothing about the length of
			 * the name appended here: a short directory and a
			 * long name passed it and then overran these
			 * buffers.  */
			if (l2s_directory_length + strlen(PREFIX) + strlen(name) + 11 >= PATH_MAX ||
			    strlen(host) + strlen(PREFIX) + strlen(name) + 11 >= PATH_MAX)
				return -ENAMETOOLONG;

			/* Ask for the descriptor here, so a directory that
			 * can't be opened is reported with the reason it
			 * can't -- ENOTDIR for the symbolic link a tracee
			 * left under that name -- instead of surfacing as
			 * whichever of the operations below fails first.  */
			status = open_l2s_directory(tracee);
			if (status == -ENOENT) {
				/* The configured l2s directory doesn't exist
				 * (never created, or deleted by the guest):
				 * recreate it and retry.  The host form is
				 * already cached, so the retry succeeds.  */
				if (mkdir(host, 0700) == 0)
					status = open_l2s_directory(tracee);
			}
			if (status < 0)
				return status;

			strcpy(intermediate, l2s_directory);
			strcat(intermediate, "/");

			strcpy(intermediate_host, host);
			strcat(intermediate_host, "/");

			strcat(intermediate, PREFIX);
			strcat(intermediate, name);
			strcat(intermediate_host, PREFIX);
			strcat(intermediate_host, name);

		} else {
			status = l2s_sibling_base(original, name, intermediate);
			if (status < 0)
				return status;
			strcpy(intermediate_host, intermediate);
		}
	}

	if (first_link) {
		/* Move the original content to the new path.  The intermediate
		 * symlink doubles as an atomic name reservation, and it briefly
		 * exists before the payload does — every chain reader already
		 * fail-softs on a dangling intermediate, so the window is
		 * benign.  The l2s directory's descriptor (open above) keeps
		 * accepting entries even if the guest deletes the directory
		 * from its own view, so no recreate/degrade fallback is
		 * needed here.  */
		strcpy(new_intermediate, intermediate);
		strcpy(base_host, intermediate_host);
		status = l2s_reserve_and_move(tracee, original, new_intermediate, base_host,
		                              intermediate, intermediate_host,
		                              final, final_host);
		if (status < 0)
			return status;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) original, (intptr_t) final_host);
		if (status < 0)
			return status;

		/* Symlink the original path to the intermediate one.  The
		 * reservation symlink created by l2s_reserve_and_move already
		 * points the intermediate at the final file, so there is
		 * nothing more to link here.  */
		status = symlink(intermediate, original);
		if (status < 0)
			return host_errno();
	} else {
		/*Move the original content to new location, by incrementing count at end of path.
		 * `intermediate` holds the CONTENT read from the joined stub. */
		status = l2s_content_to_host(tracee, intermediate, intermediate_host);
		if (status < 0)
			return status;
		size = my_readlink(tracee, intermediate_host, final);
		if (size < 0)
			return size;
		status = l2s_content_to_host(tracee, final, final_host);
		if (status < 0)
			return status;

		if (strlen(final) < 4 || strlen(final_host) < 4)
			return -EINVAL;
		link_count = atoi(final + strlen(final) - 4);
		link_count++;

		strcpy(new_final, final);
		l2s_set_suffix(new_final, link_count);
		strcpy(new_final_host, final_host);
		l2s_set_suffix(new_final_host, link_count);

		status = l2s_rename(tracee, final_host, new_final_host);
		if (status < 0)
			return host_errno();
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final_host, (intptr_t) new_final_host);
		if (status < 0)
			return status;
		strcpy(final, new_final);
		strcpy(final_host, new_final_host);
		/* Symlink the intermediate to the final file.  */
		status = l2s_unlink(tracee, intermediate_host);
		if (status < 0)
			return host_errno();
		status = l2s_symlink(tracee, final, intermediate_host);
		if (status < 0)
			return host_errno();
	}

	/* Perform symlink() operation within PRoot.  */
	status = read_path(tracee, newpath, peek_reg(tracee, CURRENT, link_target_sysarg));
	if (status >= 0)
		status = symlink(intermediate, newpath) < 0 ? host_errno() : 0;
	if (status < 0) {
		decrement_link_count(tracee, sysarg);
		return status;
	}
	poke_reg(tracee, SYSARG_RESULT, 0);
	set_sysnum(tracee, PR_void);

	return 0;
}


/* If path points a file that is a symlink to a file that begins
 *   with PREFIX, let the file be deleted, but also delete the
 *   symlink that was created and decremnt the count that is tacked
 *   to end of original file.
 */
static int decrement_link_count(Tracee *tracee, Reg sysarg)
{
	char original[PATH_MAX];
	char intermediate[PATH_MAX];
	char intermediate_host[PATH_MAX];
	char final[PATH_MAX];
	char final_host[PATH_MAX];
	char new_final[PATH_MAX];
	char new_final_host[PATH_MAX];
	char * name;
	struct stat statl;
	ssize_t size;
	int status;
	int link_count;

	/* Note: this path was already canonicalized.  */
	size = read_string(tracee, original, peek_reg(tracee, CURRENT, sysarg), PATH_MAX);
	if (size < 0)
		return size;
	if (size >= PATH_MAX)
		return -ENAMETOOLONG;

	/* Check if it is a converted link already.  */
	status = lstat(original, &statl);
	if (status < 0)
		return 0;

	if (!S_ISLNK(statl.st_mode))
		return 0;

	size = my_readlink(tracee, original, intermediate);
	if (size < 0)
		return size;

	name = strrchr(intermediate, '/');
	if (name == NULL)
		name = intermediate;
	else
		name++;

	/* Check if an l2s file is pointed to */
	if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
		return 0;

	/* Pin the l2s directory before its entries are touched, so the
	 * writes below land on the inode the chain was built against even
	 * when no link(2) ran earlier in this instance.  Best effort: on
	 * failure the writes below fall back to the plain syscalls.  */
	(void) open_l2s_directory(tracee);

	/* Read intermediate link - if this fails then
	 * this link2symlink is broken and we silently
	 * skip as we were removing it anyway.
	 * `intermediate` holds the CONTENT read from the stub.  */
	status = l2s_content_to_host(tracee, intermediate, intermediate_host);
	if (status < 0) {
		VERBOSE(tracee, 1, "Skiping deref of broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
		return 0;
	}
	size = my_readlink(tracee, intermediate_host, final);
	if (size < 0) {
		VERBOSE(tracee, 1, "Skiping deref of broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
		return 0;
	}
	status = l2s_content_to_host(tracee, final, final_host);
	if (status < 0) {
		VERBOSE(tracee, 1, "Skiping deref of broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
		return 0;
	}

	if (strlen(final) < 4 || strlen(final_host) < 4)
		return 0;	/* malformed chain: let the plain unlink proceed */
	link_count = atoi(final + strlen(final) - 4);
	link_count--;

	/* Check if it is or is not the last link to delete */
	if (link_count > 0) {
		strcpy(new_final, final);
		l2s_set_suffix(new_final, link_count);
		strcpy(new_final_host, final_host);
		l2s_set_suffix(new_final_host, link_count);

		status = l2s_rename(tracee, final_host, new_final_host);
		if (status < 0)
			return host_errno();
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final_host, (intptr_t) new_final_host);
		if (status < 0)
			return status;

		strcpy(final, new_final);

		/* Symlink the intermediate to the final file.  */
		status = l2s_unlink(tracee, intermediate_host);
		if (status < 0)
			return host_errno();

		status = l2s_symlink(tracee, final, intermediate_host);
		if (status < 0)
			return host_errno();
	} else {
		/* If it is the last, delete the intermediate and final */
		status = l2s_unlink(tracee, intermediate_host);
		if (status < 0)
			return host_errno();
		status = l2s_unlink(tracee, final_host);
		if (status < 0)
			return host_errno();
		status = notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t) final_host, 0);
		if (status < 0)
			return status;
		}

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
		char intermediate_host[PATH_MAX];
		char final[PATH_MAX];
		char final_host[PATH_MAX];
		char * name;
		struct stat finalStat;

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
				strcpy(intermediate_host,original);
				goto intermediate_proc;
			} else {
				strcpy(final,original);
				strcpy(final_host,original);
				goto final_proc;
			}
		}

		if (!S_ISLNK(statl.st_mode))
			return 0;

		size = my_readlink(tracee, original, intermediate);
		if (size < 0)
			return size;

		name = strrchr(intermediate, '/');
		if (name == NULL)
			name = intermediate;
		else
			name++;

		if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
			return 0;

		if (l2s_content_to_host(tracee, intermediate, intermediate_host) < 0)
			return 0;

		/* Fail soft on a broken l2s chain (a stub whose .l2s.
		 * intermediate/final backing file has gone missing — e.g.
		 * an interrupted dpkg run, or a rootfs copied/tarred without
		 * the hidden .l2s.* files). Returning the error here would
		 * propagate it to the guest's stat/lstat, which makes the
		 * stub un-stat-able and therefore un-rm-able (ls/rm/find all
		 * fail with an error on it). Leave the real syscall result
		 * instead, so it behaves like an ordinary dangling symlink
		 * and can be removed. (GlassHaven/Haven#329.) */
		intermediate_proc: size = my_readlink(tracee, intermediate_host, final);
		if (size < 0)
			return 0;
		if (l2s_content_to_host(tracee, final, final_host) < 0)
			return 0;

		final_proc: status = lstat(final_host,&finalStat);
		if (status < 0)
			return 0;

		if (strlen(final) < 4)
			return 0;
		finalStat.st_nlink = atoi(final + strlen(final) - 4);

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

	default:
		return 0;
	}
}

static void link2symlink_handle_statx(struct statx_syscall_state *state)
{
	if (!(state->statx_buf.stx_mask & STATX_NLINK))
		return;

	if (!is_l2s_file(state->host_path))
		return;

	size_t ending_len = strlen(state->host_path);
	state->statx_buf.stx_nlink = atoi(&state->host_path[ending_len - 4]);

	/* The statx() that PRoot let the kernel perform did succeed, so
	 * its result was read back from the tracee and is not written
	 * again unless it is explicitly reported as updated.  */
	state->updated_stats = true;
}

/**
 * Remember the name the tracee of @extension used for the file it is
 * about to open, when @host_path -- the path this open was redirected
 * to during the canonicalization -- is a file of the l2s directory.
 * The kernel knows nothing about faked hard links, so it would report
 * @host_path in "/proc/<PID>/fd/<FD>", c.f. readlink_proc_fd().
 */
static void remember_opened_link(Extension *extension, const char host_path[PATH_MAX])
{
	Tracee *tracee = TRACEE(extension);
	Link2SymlinkConfig *config;
	char final[PATH_MAX];
	char final_host[PATH_MAX];

	if (!is_l2s_file(host_path))
		return;

	config = get_config(extension, false);
	if (config == NULL || config->final_component[0] == '\0')
		return;

	/* Ensure the name that was dereferenced while this path was
	 * canonicalized is indeed a faked hard link to this very file:
	 * the tracee may have named the l2s file directly.  Chain
	 * content is compared in its host form, since it may be stored
	 * guest-form (c.f. l2s_content_to_host).  */
	if (resolve_faked_hard_link(tracee, config->final_component, final) < 0)
		return;
	if (l2s_content_to_host(tracee, final, final_host) < 0)
		return;
	if (strcmp(final_host, host_path) != 0)
		return;

	strcpy(config->pending_link, config->final_component);

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
	char final[PATH_MAX];
	char final_host[PATH_MAX];
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

	/* Resolving a hop calls translate_path(), which notifies
	 * TRANSLATED_PATH again for the very path being resolved; guard
	 * against re-entering this handler or the recursion never ends.  */
	static bool in_progress;
	if (in_progress)
		return;

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

	in_progress = true;

	/* The canonicalization dereferenced the faked hard links this
	 * path was made of, including its last component when this
	 * syscall is about to return a descriptor on it.  */
	if (is_open_syscall(sysnum))
		remember_opened_link(extension, translated_path);

	if (resolve_faked_hard_link(tracee, translated_path, final) < 0)
		goto out;

	/* Chain content is written in the form the in-guest canonicalizer
	 * dereferences it in -- a guest path when PROOT_L2S_DIR is given
	 * as one -- so hand the caller a host path either way.  */
	if (l2s_content_to_host(tracee, final, final_host) < 0)
		goto out;

	strcpy(translated_path, final_host);
out:
	in_progress = false;
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
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case SYSCALL_ENTER_START: {
		/* Forget any dereference that was not consumed by the exit
		 * stage of the syscall it was made for.  */
		Link2SymlinkConfig *config = get_config(extension, false);
		if (config != NULL)
			config->pending_link[0] = '\0';

		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);

		switch (get_sysnum(tracee, ORIGINAL)) {
		case PR_rename:
			/*int rename(const char *oldpath, const char *newpath);
			 *If newpath is a psuedo hard link decrement the link count.
			 */

			status = decrement_link_count(tracee, SYSARG_2);
			if (status < 0)
				return status;

			break;

		case PR_renameat:
		case PR_renameat2:
			/*int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
			 *If newpath is a psuedo hard link decrement the link count.
			 */

			status = decrement_link_count(tracee, SYSARG_4);
			if (status < 0)
				return status;

			break;

		case PR_unlink:
			/* If path points a file that is an symlink to a file that begins
			 *   with PREFIX, let the file be deleted, but also decrement the
			 *   hard link count, if it is greater than 1, otherwise delete
			 *   the original file and intermediate file too.
			 */

			status = decrement_link_count(tracee, SYSARG_1);
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
			 *   to end of original file.
			 */

			status = decrement_link_count(tracee, SYSARG_2);
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

	case GUEST_PATH: {
		/* A new path is about to be canonicalized.  */
		Link2SymlinkConfig *config = get_config(extension, false);
		if (config != NULL)
			config->final_component[0] = '\0';

		return 0;
	}

	case HOST_PATH: {
		/* Remember how the tracee named the last component of the
		 * path being canonicalized, that is, before PRoot follows
		 * it -- a faked hard link is a symbolic link.  Only the
		 * first notification describes it, the last one describes
		 * what it points to.  This is only worth doing when a
		 * descriptor is about to be opened on that file.  */
		Link2SymlinkConfig *config;

		if (!(bool) data2)
			return 0;

		if (!is_open_syscall(get_sysnum(TRACEE(extension), ORIGINAL)))
			return 0;

		config = get_config(extension, true);
		if (config == NULL || config->final_component[0] != '\0')
			return 0;

		strcpy(config->final_component, (const char *) data1);

		return 0;
	}

	case TRANSLATED_PATH:
		translated_path(extension, (char *) data1);
		return 0;

	case STATX_SYSCALL:
		link2symlink_handle_statx((struct statx_syscall_state *) data1);
		return 0;

	case READLINK_PROC_FD:
		readlink_proc_fd(TRACEE(extension), (struct readlink_proc_fd_state *) data1);
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
