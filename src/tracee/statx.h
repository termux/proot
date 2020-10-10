#ifndef STATX_H
#define STATX_H

#include "tracee/tracee.h"
#include "sys/vfs.h"
#include "path/path.h"
#include "extension/extension.h"

/*
 * This structure is passed to extensions
 * for STATX_SYSCALL event
 */
struct statx_syscall_state {
	/* Host path to statx()'d file */
	char host_path[PATH_MAX];

	/* This is statx structure that will be returned
	 * Extensions can fill additional data in it
	 */
	struct statx statx_buf;

	/* Mask parameter passed to statx(),
	 * selects fields which should be filled
	 */
	word_t mask;

	/* True if AT_SYMLINK_NOFOLLOW flag was used
	 * requesting lstat()-like behavior of not following symlink
	 */
	bool do_lstat;
};

int handle_statx_syscall(Tracee *tracee);


#endif // STATX_H
