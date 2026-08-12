#include <stdio.h>     /* rename(2), */
#include <stdlib.h>    /* atoi */
#include <unistd.h>    /* symlink(2), symlinkat(2), readlink(2), lstat(2), unlink(2), unlinkat(2)*/
#include <string.h>    /* str*, strrchr, strcat, strcpy, strncpy, strncmp */
#include <sys/types.h> /* lstat(2), */
#include <sys/stat.h>  /* lstat(2), */
#include <sys/ptrace.h>/* PTRACE_SYSCALL, */
#include <errno.h>     /* E*, */
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
 * Copy the contents of the @symlink into @value (nul terminated).
 * This function returns -errno if an error occured, otherwise 0.
 */
static int my_readlink(const char symlink[PATH_MAX], char value[PATH_MAX])
{
	ssize_t size;

	size = readlink(symlink, value, PATH_MAX);
	if (size < 0)
		return size;
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
static int resolve_faked_hard_link(const char link[PATH_MAX], char final[PATH_MAX])
{
	char intermediate[PATH_MAX];
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

	return my_readlink(intermediate, final);
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
	const char * l2s_directory;
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
	} else {
		/* compute new name */
		name = strrchr(original,'/');
		if (name == NULL)
			name = original;
		else
			name++;

		l2s_directory = getenv("PROOT_L2S_DIR");
		if (l2s_directory != NULL && l2s_directory[0]) {
			if (strlen(PREFIX) + strlen(l2s_directory) + (strlen(original) - strlen(name)) + 6 >= PATH_MAX)
				return -ENAMETOOLONG;

			strcpy(intermediate, l2s_directory);
			if (l2s_directory[strlen(l2s_directory) - 1] != '/') {
				strcat(intermediate, "/");
			}
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
		/*Move the original content to the new path. */
		do {
			sprintf(new_intermediate, "%s%04d", intermediate, intermediate_suffix);
			intermediate_suffix++;
		} while ((access(new_intermediate,F_OK) != -1) && (intermediate_suffix < 1000));
		strcpy(intermediate, new_intermediate);

		strcpy(final, intermediate);
		strcat(final, ".0002");
		status = rename(original, final);
		if (status < 0)
			return status;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) original, (intptr_t) final);
		if (status < 0)
			return status;

		/* Symlink the intermediate to the final file.  */
		status = symlink(final, intermediate);
		if (status < 0)
			return status;

		/* Symlink the original path to the intermediate one.  */
		status = symlink(intermediate, original);
		if (status < 0)
			return status;
	} else {
		/*Move the original content to new location, by incrementing count at end of path. */
		size = my_readlink(intermediate, final);
		if (size < 0)
			return size;

		link_count = atoi(final + strlen(final) - 4);
		link_count++;

		strncpy(new_final, final, strlen(final) - 4);
		sprintf(new_final + strlen(final) - 4, "%04d", link_count);

		status = rename(final, new_final);
		if (status < 0)
			return status;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final, (intptr_t) new_final);
		if (status < 0)
			return status;
		strcpy(final, new_final);
		/* Symlink the intermediate to the final file.  */
		status = unlink(intermediate);
		if (status < 0)
			return status;
		status = symlink(final, intermediate);
		if (status < 0)
			return status;
	}

	/* Perform symlink() operation within PRoot.  */
	status = read_path(tracee, final, peek_reg(tracee, CURRENT, link_target_sysarg));
	if (status >= 0) {
		status = symlink(intermediate, final);
		if (status < 0) status = -errno;
	}
	if (status < 0) {
		status = -errno;
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
	char final[PATH_MAX];
	char new_final[PATH_MAX];
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

	size = my_readlink(original, intermediate);
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

	/* Read intermediate link - if this fails then
	 * this link2symlink is broken and we silently
	 * skip as we were removing it anyway.  */
	size = my_readlink(intermediate, final);
	if (size < 0) {
		VERBOSE(tracee, 1, "Skiping deref of broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
		return 0;
	}

	link_count = atoi(final + strlen(final) - 4);
	link_count--;

	/* Check if it is or is not the last link to delete */
	if (link_count > 0) {
		strncpy(new_final, final, strlen(final) - 4);
		sprintf(new_final + strlen(final) - 4, "%04d", link_count);

		status = rename(final, new_final);
		if (status < 0)
			return status;
		status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t) final, (intptr_t) new_final);
		if (status < 0)
			return status;

		strcpy(final, new_final);

		/* Symlink the intermediate to the final file.  */
		status = unlink(intermediate);
		if (status < 0)
			return status;

		status = symlink(final, intermediate);
		if (status < 0)
			return status;
	} else {
		/* If it is the last, delete the intermediate and final */
		status = unlink(intermediate);
		if (status < 0)
			return status;
		status = unlink(final);
		if (status < 0)
			return status;
		status = notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t) final, 0);
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
		char final[PATH_MAX];
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
				goto intermediate_proc;
			} else {
				strcpy(final,original);
				goto final_proc;
			}
		}

		if (!S_ISLNK(statl.st_mode))
			return 0;

		size = my_readlink(original, intermediate);
		if (size < 0)
			return size;

		name = strrchr(intermediate, '/');
		if (name == NULL)
			name = intermediate;
		else
			name++;

		if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
			return 0;

		intermediate_proc: size = my_readlink(intermediate, final);
		if (size < 0)
			return size;

		final_proc: status = lstat(final,&finalStat);
		if (status < 0)
			return status;

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

	if (!is_l2s_file(host_path))
		return;

	config = get_config(extension, false);
	if (config == NULL || config->final_component[0] == '\0')
		return;

	/* Ensure the name that was dereferenced while this path was
	 * canonicalized is indeed a faked hard link to this very file:
	 * the tracee may have named the l2s file directly.  */
	if (resolve_faked_hard_link(config->final_component, final) < 0)
		return;
	if (strcmp(final, host_path) != 0)
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
	 * path was made of, including its last component when this
	 * syscall is about to return a descriptor on it.  */
	if (is_open_syscall(sysnum))
		remember_opened_link(extension, translated_path);

	if (resolve_faked_hard_link(translated_path, final) < 0)
		return;

	strcpy(translated_path, final);
	return;
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
		readlink_proc_fd((struct readlink_proc_fd_state *) data1);
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
