#include <errno.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <talloc.h>

#include "syscall/sysnum.h"
#include "tracee/mem.h"
#include "extension/fake_id0/chmod.h"

#include "extension/fake_id0/helper_functions.h"

#ifdef USERLAND
#define ACL_ACCESS_XATTR "system.posix_acl_access"

/** Puts in path the host path of the file path_sysarg names, or of the file
 *  fd_sysarg is open on when path_sysarg is IGNORE_SYSARG. Returns 1 if that
 *  file isn't in the guestfs, -errno on error, 0 otherwise.
 */
static int get_target_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg,
	Reg fd_sysarg)
{
	int status;

	if(path_sysarg == IGNORE_SYSARG)
		return get_fd_path(tracee, path, fd_sysarg, CURRENT);

	status = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
	/* chmod("/proc/self/fd/<n>") is how programs change the mode of
	 * a file they have open where the kernel lacks fchmodat2(2).  */
	if(status == 1) {
		int resolved = resolve_proc_fd_path(tracee, path);
		if(resolved >= 0)
			status = resolved;
	}
	return status;
}

/** Returns the mode to give the real file at path when its meta file records
 *  mode. The kernel still checks the real mode, execute permission in
 *  particular, so it follows the recorded one, except that its owner, which
 *  every emulated user really is, keeps read and write access (and search
 *  access to directories), and that set-id bits stay in the meta file.
 */
static mode_t get_real_mode(mode_t mode, char path[PATH_MAX])
{
	struct stat statl;
	mode_t real_mode;

	real_mode = (mode & 01777) | S_IRUSR | S_IWUSR;
	if((mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
	   || (lstat(path, &statl) == 0 && S_ISDIR(statl.st_mode)))
		real_mode |= S_IXUSR;
	return real_mode;
}

/** Handles chmod, fchmod, fchmodat, and fchmodat2 syscalls. If the meta file
 *  of the file exists, lets the kernel apply the new permissions to the real
 *  file and has handle_chmod_exit_end() write them to the meta file. See
 *  chmod(2) for returned permission errors.
 */
int handle_chmod_enter_end(Tracee *tracee, Reg path_sysarg, Reg mode_sysarg, 
	Reg fd_sysarg, Reg dirfd_sysarg, Config *config)
{
	int status;
	mode_t call_mode, read_mode;
	uid_t owner;
	gid_t group;
	char path[PATH_MAX];
	char rel_path[PATH_MAX];
	char meta_path[PATH_MAX];

	TALLOC_FREE(config->pending_path);

	// path_sysarg is set to IGNORE for fchmod.
	status = get_target_path(tracee, path, path_sysarg, fd_sysarg);
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

	poke_reg(tracee, mode_sysarg, get_real_mode(call_mode, path));
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

/** Handles setxattr, lsetxattr, and fsetxattr syscalls. Setting the
 *  system.posix_acl_access attribute of a file sets its permission bits as
 *  well, see acl(5). If the meta file of the file exists, checks the caller
 *  may change its mode and has handle_acl_exit_end() copy the permission bits
 *  the kernel derives from the ACL to the meta file.
 */
int handle_acl_enter_end(Tracee *tracee, Reg path_sysarg, Reg fd_sysarg,
	Config *config)
{
	int status;
	mode_t read_mode;
	uid_t owner;
	gid_t group;
	char name[sizeof(ACL_ACCESS_XATTR)];
	char path[PATH_MAX];
	char meta_path[PATH_MAX];

	TALLOC_FREE(config->pending_path);

	status = read_string(tracee, name, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(name));
	if(status != (int) sizeof(name) || name[sizeof(name) - 1] != '\0'
	   || strcmp(name, ACL_ACCESS_XATTR) != 0)
		return 0;

	status = get_target_path(tracee, path, path_sysarg, fd_sysarg);
	if(status != 0 || get_meta_path(path, meta_path) < 0
	   || path_exists(meta_path) < 0)
		return 0;

	read_meta_file(meta_path, &read_mode, &owner, &group, config);
	if(config->euid != owner && config->euid != 0)
		return -EPERM;

	config->pending_path = talloc_strdup(config, path);
	if(config->pending_path == NULL)
		return -ENOMEM;
	return 0;
}

/** Copies to the meta file the permission bits the real file got from the
 *  ACL that handle_acl_enter_end() let through, if the syscall succeeded,
 *  then gives back to the real owner the access get_real_mode() keeps.
 */
int handle_acl_exit_end(Tracee *tracee, Config *config)
{
	struct stat statl;
	mode_t mode, real_mode;
	uid_t owner;
	gid_t group;
	char meta_path[PATH_MAX];

	if(config->pending_path == NULL)
		return 0;

	if((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
	   && get_meta_path(config->pending_path, meta_path) == 0
	   && path_exists(meta_path) == 0
	   && lstat(config->pending_path, &statl) == 0) {
		read_meta_file(meta_path, &mode, &owner, &group, config);
		mode = (mode & 07000) | (statl.st_mode & 0777);
		if(write_meta_file(meta_path, mode, owner, group, 0, config) == 0) {
			real_mode = get_real_mode(mode, config->pending_path);
			if(real_mode != (statl.st_mode & 07777))
				(void) chmod(config->pending_path, real_mode);
		}
	}

	TALLOC_FREE(config->pending_path);
	return 0;
}
#endif /* ifdef USERLAND */
