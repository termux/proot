#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/helper_functions.h"

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

/** Swaps the meta files of the paths a renameat2(RENAME_EXCHANGE) swaps.
 *  When only one of them has a meta file, the other path gets it.
 */
static int exchange_meta_files(char meta_path[PATH_MAX], char newpath[PATH_MAX], Config *config)
{
	int status;
	int old_exists;
	int new_exists;
	uid_t uid, new_uid;
	gid_t gid, new_gid;
	mode_t mode, new_mode;
	char new_meta_path[PATH_MAX];

	status = get_meta_path(newpath, new_meta_path);
	if(status < 0)
		return status;

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

	return 0;
}

/** Handles rename, renameat and renameat2 syscalls. If a meta file matching
 *  the file to be renamed exists, renames the meta file as well. See rename(2)
 *  for returned permission errors.
 */
int handle_rename_enter_end(Tracee *tracee, Reg oldfd_sysarg, Reg oldpath_sysarg, 
	Reg newfd_sysarg, Reg newpath_sysarg, Reg flags_sysarg, Config *config)
{
	int status;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	unsigned int flags = 0;
	struct stat statl;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char rel_oldpath[PATH_MAX];
	char rel_newpath[PATH_MAX];
	char meta_path[PATH_MAX];

	if(flags_sysarg != IGNORE_SYSARG)
		flags = peek_reg(tracee, CURRENT, flags_sysarg);

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

	// If a meta file exists, "copy" it to the new path.
	status = get_meta_path(oldpath, meta_path);
	if(status < 0)
		return status;

	// The kernel will fail with EEXIST: leave both meta files alone.
	if((flags & RENAME_NOREPLACE) != 0 && lstat(newpath, &statl) == 0)
		return 0;

	if((flags & RENAME_EXCHANGE) != 0)
		return exchange_meta_files(meta_path, newpath, config);

	if(path_exists(meta_path) != 0)
		return 0;

	read_meta_file(meta_path, &mode, &uid, &gid, config);
	unlink(meta_path);
	
	strcpy(meta_path, "");
	status = get_meta_path(newpath, meta_path);
	if(status < 0)
		return status;

	return write_meta_file(meta_path, mode, uid, gid, 0, config); 
}
