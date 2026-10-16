#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "extension/fake_id0/unlink.h"
#include "extension/fake_id0/helper_functions.h"

/** Deletes the meta files in the directory at path if nothing else is
 *  there and none of their files exists, so that the directory can be
 *  removed. Such orphaned meta files are invisible to the guest when
 *  hidden_files is on, and they would make rmdir(2) fail with ENOTEMPTY.
 */
static void remove_orphaned_meta_files(char path[PATH_MAX])
{
	DIR *dir;
	struct dirent *entry;
	struct stat statl;
	size_t tag_length = strlen(META_TAG);
	char entry_path[PATH_MAX];
	int pass;

	dir = opendir(path);
	if (dir == NULL)
		return;

	/* Check every entry first, then delete them.  */
	for (pass = 0; pass < 2; pass++) {
		rewinddir(dir);
		while ((entry = readdir(dir)) != NULL) {
			const char *name = entry->d_name;
			int status;

			if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
				continue;

			if (strncmp(name, META_TAG, tag_length) != 0)
				goto end;

			/* A meta file for an empty name belongs to nothing.  */
			if (name[tag_length] != '\0') {
				status = snprintf(entry_path, PATH_MAX, "%s/%s", path, name + tag_length);
				if (status < 0 || status >= PATH_MAX)
					goto end;
				if (lstat(entry_path, &statl) == 0 || errno != ENOENT)
					goto end;
			}

			if (pass == 1) {
				status = snprintf(entry_path, PATH_MAX, "%s/%s", path, name);
				if (status < 0 || status >= PATH_MAX)
					goto end;
				unlink(entry_path);
			}
		}
	}
end:
	closedir(dir);
}

/** Handles unlink, unlinkat, and rmdir syscalls. Checks permissions in meta 
 *  files matching the file to be unlinked if the meta file exists. Unlinks
 *  the meta file if the call would be successful. See unlink(2) and rmdir(2)
 *  for returned errors.
 */
int handle_unlink_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, Config *config)
{
	int status;
	struct stat statl;
	char orig_path[PATH_MAX];
	char rel_path[PATH_MAX];
	char meta_path[PATH_MAX];
	
	status = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT); 
	if(status < 0) 
		return status;
	if(status == 1)
		return 0;

	status = get_meta_path(orig_path, meta_path);
	if(status < 0) 
		return status;
	
	status = get_fd_path(tracee, rel_path, fd_sysarg, CURRENT);
	if(status < 0) 
		return status;
	
	status = check_dir_perms(tracee, 'w', orig_path, rel_path, config);
	if(status < 0) 
		return status;

	if(lstat(orig_path, &statl) == 0 && S_ISDIR(statl.st_mode))
		remove_orphaned_meta_files(orig_path);
 
	/** If the meta_file relating to the file being unlinked exists,
	 *  unlink that as well.
	 */
	if(path_exists(meta_path) == 0) 
		unlink(meta_path);

	return 0;
}
