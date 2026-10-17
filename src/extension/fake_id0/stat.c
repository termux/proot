#include <linux/limits.h>
#include <fcntl.h>       /* AT_EMPTY_PATH, */
#include <string.h>      /* strcpy(3), */
#include <sys/types.h>   /* uid_t, gid_t, get*id(2), */
#include <unistd.h>	  /* get*id(2),  */
#include <assert.h>	  /* assert(3), */

#include "tracee/mem.h"
#include "path/path.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "extension/fake_id0/stat.h"
#include "extension/fake_id0/helper_functions.h"
#include "tracee/statx.h"

#ifndef USERLAND
int handle_stat_exit_end(Tracee *tracee, Config *config, Reg stat_sysarg) {
	word_t address;
	uid_t uid;
	gid_t gid;
	word_t result;

	/* Override only if it succeed.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0)
		return 0;

	address = peek_reg(tracee, ORIGINAL, stat_sysarg);

	/* Sanity checks.  */
	assert(__builtin_types_compatible_p(uid_t, uint32_t));
	assert(__builtin_types_compatible_p(gid_t, uint32_t));

	/* Get the uid & gid values from the 'stat' structure.  */
	uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee));
	if (errno != 0)
		uid = 0; /* Not fatal.  */

	gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee));
	if (errno != 0)
		gid = 0; /* Not fatal.  */

	/* Override only if the file is owned by the current user.
	 * Errors are not fatal here.  */
	if (uid == getuid())
		poke_uint32(tracee, address + offsetof_stat_uid(tracee), config->suid);

	if (gid == getgid())
		poke_uint32(tracee, address + offsetof_stat_gid(tracee), config->sgid);

	return 0;
}
#endif /* ifndef USERLAND */

#ifdef USERLAND
/** Convert fstat and fstat64 to readlink
 *  this is so we can get the path associated with /proc/pid#/fd/fd#
 */
int handle_stat_enter_end(Tracee *tracee, Reg fd_sysarg) {
	char path[PATH_MAX];
	char link_path[64];
	word_t link_address;
	word_t path_address;

	set_sysnum(tracee, PR_readlinkat);
	snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", tracee->pid, (int)peek_reg(tracee, CURRENT, fd_sysarg));
	link_address = alloc_mem(tracee, sizeof(link_path));
	path_address = alloc_mem(tracee, sizeof(path));
	write_data(tracee, link_address, link_path, sizeof(link_path));
	poke_reg(tracee, SYSARG_1, AT_FDCWD);	
	poke_reg(tracee, SYSARG_2, link_address);	
	poke_reg(tracee, SYSARG_3, path_address);	
	poke_reg(tracee, SYSARG_4, sizeof(path));	
	return 0;
}

int handle_stat_exit_end(Tracee *tracee, Config *config, word_t sysnum) {
	int status = 0;
	word_t address;
	Reg sysarg;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	struct stat my_stat;
	char path[PATH_MAX];
	char meta_path[PATH_MAX];
	word_t result;

	/* Override only if it succeed.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0) 
		return 0;

	/* Get the pathname of the file to be 'stat'. */
	if(sysnum == PR_fstat || sysnum == PR_fstat64) {
		status = read_sysarg_path(tracee, path, SYSARG_2, CURRENT);
	} else if(sysnum == PR_fstatat64 || sysnum == PR_newfstatat) 
		status = read_sysarg_path(tracee, path, SYSARG_2, MODIFIED);
	else 
		status = read_sysarg_path(tracee, path, SYSARG_1, MODIFIED);

	/* fstatat(fd, "", buf, AT_EMPTY_PATH) stats the descriptor itself: use
	 * the path of the file it is open on if that is in the guestfs. Other
	 * descriptors (pipes, sockets, ...) keep the empty path, which gets the
	 * uid/gid mapping below.  */
	if((sysnum == PR_fstatat64 || sysnum == PR_newfstatat) && status == 0 && path[0] == '\0'
	   && (peek_reg(tracee, MODIFIED, SYSARG_4) & AT_EMPTY_PATH) != 0) {
		char fd_path[PATH_MAX];

		if(get_fd_path(tracee, fd_path, SYSARG_1, MODIFIED) == 0)
			strcpy(path, fd_path);
	}

	if(status < 0) 
		return status;
	if(status == 1) 
		return 0;

	/* Get the address of the 'stat' structure.  */
	if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
		sysarg = SYSARG_3;
	else
		sysarg = SYSARG_2;

	/** If the meta file exists, read the data from it and replace it the
	 *  relevant data in the stat structure.
	 */
	
	status = get_meta_path(path, meta_path);
	if(status == 0) {
		status = path_exists(meta_path);
		if(status == 0) {
			read_meta_file(meta_path, &mode, &uid, &gid, config);

			/** Get the file type and sticky/set-id bits of the original 
			 *  file and add them to the mode found in the meta_file.
			 */
			read_data(tracee, &my_stat, peek_reg(tracee, ORIGINAL, sysarg), sizeof(struct stat));
			my_stat.st_mode = (mode | ((my_stat.st_mode & S_IFMT) | (my_stat.st_mode & 07000)));
			my_stat.st_uid = uid;
			my_stat.st_gid = gid;
			write_data(tracee, peek_reg(tracee, ORIGINAL, sysarg), &my_stat, sizeof(struct stat));
			return 0;
		}
	}

	address = peek_reg(tracee, ORIGINAL, sysarg);

	/* Sanity checks.  */
	assert(__builtin_types_compatible_p(uid_t, uint32_t));
	assert(__builtin_types_compatible_p(gid_t, uint32_t));

	/* Get the uid & gid values from the 'stat' structure.  */
	uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee));
	if (errno != 0) 
		uid = 0; /* Not fatal.  */
	
	gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee));
	if (errno != 0) 
		gid = 0; /* Not fatal.  */
	
	/* Override only if the file is owned by the current user.
	 * Errors are not fatal here.  */
	if (uid == getuid()) 
		poke_uint32(tracee, address + offsetof_stat_uid(tracee), config->suid);
	
	if (gid == getgid()) 
		poke_uint32(tracee, address + offsetof_stat_gid(tracee), config->sgid);
	
	return 0;
}
#endif /* ifdef USERLAND */

int fake_id0_handle_statx_syscall(Tracee *tracee, Config *config, uintptr_t statx_state_raw) {
	struct statx_syscall_state *state = (struct statx_syscall_state *) statx_state_raw;
#ifdef USERLAND
	char meta_path[PATH_MAX];
	mode_t mode;
	uid_t uid;
	gid_t gid;

	/* Report what the meta file says, as stat(2) does.  */
	if (belongs_to_guestfs(tracee, state->host_path)
	    && get_meta_path(state->host_path, meta_path) == 0
	    && path_exists(meta_path) == 0) {
		read_meta_file(meta_path, &mode, &uid, &gid, config);
		if (state->statx_buf.stx_mask & STATX_MODE)
			state->statx_buf.stx_mode = mode | (state->statx_buf.stx_mode & (S_IFMT | 07000));
		if (state->statx_buf.stx_mask & STATX_UID)
			state->statx_buf.stx_uid = uid;
		if (state->statx_buf.stx_mask & STATX_GID)
			state->statx_buf.stx_gid = gid;
		state->updated_stats = true;
		return 0;
	}
#else
	(void) tracee;
#endif
	if (state->statx_buf.stx_mask & STATX_UID) {
		if (state->statx_buf.stx_uid == getuid()) {
			state->statx_buf.stx_uid = config->suid;
			state->updated_stats = true;
		}
	}
	if (state->statx_buf.stx_mask & STATX_GID) {
		if (state->statx_buf.stx_gid == getgid()) {
			state->statx_buf.stx_gid = config->sgid;
			state->updated_stats = true;
		}
	}
	return 0;
}
