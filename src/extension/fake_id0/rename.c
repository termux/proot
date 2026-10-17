#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/helper_functions.h"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1 << 2)
#endif

/** Swaps the meta files of the two paths a renameat2(RENAME_EXCHANGE)
 *  exchanged. When only one of them has a meta file, it moves to the other.
 */
static void exchange_meta_files(char meta_path[PATH_MAX], char new_meta_path[PATH_MAX], Config *config)
{
	int old_exists;
	int new_exists;
	uid_t uid, new_uid;
	gid_t gid, new_gid;
	mode_t mode, new_mode;

	old_exists = path_exists(meta_path) == 0;
	new_exists = path_exists(new_meta_path) == 0;

	if(old_exists)
		read_meta_file(meta_path, &mode, &uid, &gid, config);
	if(new_exists)
		read_meta_file(new_meta_path, &new_mode, &new_uid, &new_gid, config);

	if(old_exists)
		write_meta_file(new_meta_path, mode, uid, gid, 0, config);
	else if(new_exists)
		unlink(new_meta_path);

	if(new_exists)
		write_meta_file(meta_path, new_mode, new_uid, new_gid, 0, config);
	else if(old_exists)
		unlink(meta_path);
}

/** Handles rename, renameat and renameat2 syscalls at the entry stage:
 *  checks the write permission on both parent directories in their meta
 *  files. See rename(2) for the returned errors. The meta file itself is
 *  moved at the exit stage, by handle_rename_exit_end(), once the kernel
 *  has renamed the file.
 */
int handle_rename_enter_end(Tracee *tracee, Reg oldfd_sysarg, Reg oldpath_sysarg, 
	Reg newfd_sysarg, Reg newpath_sysarg, Config *config)
{
	int status;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char rel_oldpath[PATH_MAX];
	char rel_newpath[PATH_MAX];

	status = read_sysarg_path(tracee, oldpath, oldpath_sysarg, CURRENT); 
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	status = read_sysarg_path(tracee, newpath, newpath_sysarg, CURRENT); 
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	status = get_fd_path(tracee, rel_oldpath, oldfd_sysarg, CURRENT);
	if(status < 0)
		return status;

	status = get_fd_path(tracee, rel_newpath, newfd_sysarg, CURRENT);
	if(status < 0)
		return status;

	status = check_dir_perms(tracee, 'w', oldpath, rel_oldpath, config);
	if(status < 0)
		return status;

	status = check_dir_perms(tracee, 'w', newpath, rel_newpath, config);
	if(status < 0)
		return status;

	return 0;
}

/** Handles rename, renameat and renameat2 syscalls at the exit stage:
 *  moves the meta file along with the file, or swaps the two meta files
 *  after a RENAME_EXCHANGE. A call the kernel refused leaves them where
 *  they are. Always returns 0: the rename has already happened, so there
 *  is nothing left to fail.
 */
int handle_rename_exit_end(Tracee *tracee, Reg oldpath_sysarg, Reg newpath_sysarg,
	Reg flags_sysarg, Config *config)
{
	uid_t uid;
	gid_t gid;
	mode_t mode;
	unsigned int flags = 0;
	struct stat statl;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char meta_path[PATH_MAX];
	char new_meta_path[PATH_MAX];

	if((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
		return 0;

	if(flags_sysarg != IGNORE_SYSARG)
		flags = peek_reg(tracee, ORIGINAL, flags_sysarg);

	/* The paths the kernel was given, as translated at the entry stage.  */
	if(read_sysarg_path(tracee, oldpath, oldpath_sysarg, MODIFIED) != 0
	   || read_sysarg_path(tracee, newpath, newpath_sysarg, MODIFIED) != 0
	   || get_meta_path(oldpath, meta_path) < 0
	   || get_meta_path(newpath, new_meta_path) < 0)
		return 0;

	if((flags & RENAME_EXCHANGE) != 0) {
		exchange_meta_files(meta_path, new_meta_path, config);
		return 0;
	}

	/* rename(2) does nothing when both names are links to the same file:
	 * the old name still exists, and the meta file stays with it. After a
	 * RENAME_WHITEOUT the old name exists too, as a whiteout.  */
	if((flags & RENAME_WHITEOUT) == 0 && lstat(oldpath, &statl) == 0)
		return 0;

	/* Move the meta file along with the file.  */
	if(path_exists(meta_path) != 0)
		return 0;

	read_meta_file(meta_path, &mode, &uid, &gid, config);
	unlink(meta_path);
	write_meta_file(new_meta_path, mode, uid, gid, 0, config);
	return 0;
}
