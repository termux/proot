#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <talloc.h>

#include "syscall/sysnum.h"
#include "extension/fake_id0/chmod.h"

#include "extension/fake_id0/helper_functions.h"

#ifdef USERLAND
/** Handles chmod, fchmod, fchmodat, and fchmodat2 syscalls. If the meta file
 *  of the file exists, lets the kernel apply the new permissions to the real
 *  file and has handle_chmod_exit_end() write them to the meta file. See
 *  chmod(2) for returned permission errors.
 */
int handle_chmod_enter_end(Tracee *tracee, Reg path_sysarg, Reg mode_sysarg, 
	Reg fd_sysarg, Reg dirfd_sysarg, Config *config)
{
	int status;
	struct stat statl;
	mode_t call_mode, read_mode, real_mode;
	uid_t owner;
	gid_t group;
	char path[PATH_MAX];
	char rel_path[PATH_MAX];
	char meta_path[PATH_MAX];

	TALLOC_FREE(config->pending_path);

	// When path_sysarg is set to IGNORE, the call being handled is fchmod.
	if(path_sysarg == IGNORE_SYSARG) 
		status = get_fd_path(tracee, path, fd_sysarg, CURRENT);
	else {
		status = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
		/* chmod("/proc/self/fd/<n>") is how programs change the mode of
		 * a file they have open where the kernel lacks fchmodat2(2).  */
		if(status == 1) {
			int resolved = resolve_proc_fd_path(tracee, path);
			if(resolved >= 0)
				status = resolved;
		}
	}
	if(status < 0)
		return status;
	// If the file exists outside the guestfs, drop the syscall.
	else if(status == 1) {
		set_sysnum(tracee, PR_getuid);
		return 0;
	}

	status = get_meta_path(path, meta_path);
	if(path_exists(meta_path) < 0)
		return 0;

	status = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
	if(status < 0)
		return status;

	status = check_dir_perms(tracee, 'r', path, rel_path, config);
	if(status < 0) 
		return status;
	
	read_meta_file(meta_path, &read_mode, &owner, &group, config);
	if(config->euid != owner && config->euid != 0) 
		return -EPERM;

	/* Like the kernel, use only the permission bits: callers such as
	 * cp -p pass a whole st_mode, file type included.  */
	call_mode = peek_reg(tracee, ORIGINAL, mode_sysarg) & 07777;

	/* The kernel may still reject the call: write the meta file
	 * only once it has applied the mode.  */
	config->pending_path = talloc_strdup(config, path);
	if(config->pending_path == NULL)
		return -ENOMEM;
	config->pending_mode = call_mode;

	/* The kernel still checks the real mode, execute permission
	 * in particular: apply the mode to the real file too. Its owner,
	 * which every emulated user really is, keeps read and write access
	 * (and search access to directories); set-id bits stay in the
	 * meta file.  */
	real_mode = (call_mode & 01777) | S_IRUSR | S_IWUSR;
	if((call_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
	   || (lstat(path, &statl) == 0 && S_ISDIR(statl.st_mode)))
		real_mode |= S_IXUSR;
	poke_reg(tracee, mode_sysarg, real_mode);
	return 0;
}

/** Writes to the meta file the mode that handle_chmod_enter_end() left
 *  pending, if the syscall succeeded.
 */
int handle_chmod_exit_end(Tracee *tracee, Config *config)
{
	int status = 0;
	mode_t read_mode;
	uid_t owner;
	gid_t group;
	char meta_path[PATH_MAX];

	if(config->pending_path == NULL)
		return 0;

	if((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
	   && get_meta_path(config->pending_path, meta_path) == 0
	   && path_exists(meta_path) == 0) {
		read_meta_file(meta_path, &read_mode, &owner, &group, config);
		status = write_meta_file(meta_path, config->pending_mode, owner, group, 0, config);
	}

	TALLOC_FREE(config->pending_path);
	return status;
}
#endif /* ifdef USERLAND */
