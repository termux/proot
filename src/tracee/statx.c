#include <errno.h>     /* E*, */

#include "tracee/statx.h"
#include "tracee/mem.h"

int handle_statx_syscall(Tracee *tracee) {
	struct statx_syscall_state state = {};
	char guest_path[PATH_MAX] = {};
	struct stat stat_buf = {};

	/* Read arguments and translate path */
	state.do_lstat = ((peek_reg(tracee, CURRENT, SYSARG_3) & AT_SYMLINK_NOFOLLOW) != 0);
	state.mask = peek_reg(tracee, CURRENT, SYSARG_4);
	int status = read_string(tracee, guest_path, peek_reg(tracee, CURRENT, SYSARG_2), PATH_MAX);
	if (status < 0) {
		return status;
	}
	if (status >= PATH_MAX) { 
		return -ENAMETOOLONG;
	}
	status = translate_path(tracee, state.host_path, peek_reg(tracee, CURRENT, SYSARG_1), guest_path, !state.do_lstat);
	if (status < 0) {
		return status;
	}

	/* Call [l]stat() on translated path */
	if (state.do_lstat) {
		status = lstat(state.host_path, &stat_buf);
	} else {
		status = stat(state.host_path, &stat_buf);
	}
	if (status < 0) {
		return status;
	}

	/* Translate results from stat to statx */
	state.statx_buf.stx_mask = (
		state.mask & (
			STATX_TYPE | 
			STATX_MODE |
			STATX_NLINK |
			STATX_UID |
			STATX_GID |
			STATX_ATIME |
			STATX_MTIME |
			STATX_CTIME |
			STATX_INO |
			STATX_SIZE |
			STATX_BLOCKS |
			STATX_BTIME
		)
	);
	state.statx_buf.stx_blksize = stat_buf.st_blksize;
	if (state.mask & (STATX_TYPE | STATX_MODE)) {
		state.statx_buf.stx_mode = stat_buf.st_mode;
	}
	if (state.mask & STATX_NLINK) {
		state.statx_buf.stx_nlink = stat_buf.st_nlink;
	}
	if (state.mask & STATX_UID) {
		state.statx_buf.stx_uid = stat_buf.st_uid;
	}
	if (state.mask & STATX_GID) {
		state.statx_buf.stx_gid = stat_buf.st_gid;
	}
	if (state.mask & STATX_ATIME) {
		state.statx_buf.stx_atime.tv_sec = stat_buf.st_atim.tv_sec;
		state.statx_buf.stx_atime.tv_nsec = stat_buf.st_atim.tv_nsec;
	}
	if (state.mask & STATX_MTIME) {
		state.statx_buf.stx_mtime.tv_sec = stat_buf.st_mtim.tv_sec;
		state.statx_buf.stx_mtime.tv_nsec = stat_buf.st_mtim.tv_nsec;
	}
	if (state.mask & STATX_BTIME) {
		state.statx_buf.stx_ctime.tv_sec = stat_buf.st_ctim.tv_sec;
		state.statx_buf.stx_ctime.tv_nsec = stat_buf.st_ctim.tv_nsec;
	}
	if (state.mask & STATX_INO) {
		state.statx_buf.stx_ino = stat_buf.st_ino;
	}
	if (state.mask & STATX_SIZE) {
		state.statx_buf.stx_size = stat_buf.st_size;
	}
	if (state.mask & STATX_BLOCKS) {
		state.statx_buf.stx_blocks = stat_buf.st_blocks;
	}
	if (state.mask & STATX_BTIME) {
		// stat() doesn't expose this, take ctime
		state.statx_buf.stx_btime.tv_sec = stat_buf.st_ctim.tv_sec;
		state.statx_buf.stx_btime.tv_nsec = stat_buf.st_ctim.tv_nsec;
	}

	/* Notify extensions */
	status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t) &state, 0);
	if (status < 0) {
		return status;
	}

	/* Return results to tracee */
	status = write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_5), &state.statx_buf, sizeof(state.statx_buf));
	if (status < 0) {
		return status;
	}
	return 0;
}
