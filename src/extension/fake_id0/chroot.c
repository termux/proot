#include <errno.h>       /* E*, */
#include <sys/stat.h>    /* stat, */
#include <stdlib.h>      /* realpath(3), */
#include <string.h>      /* strcpy(3), */

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "extension/fake_id0/chroot.h"

int handle_chroot_exit_end(Tracee *tracee, Config *config, bool from_sigsys) {
	char path[PATH_MAX];
	char path_guest[PATH_MAX];
	char path_host_absolute[PATH_MAX];
	word_t input;
	int status;
	word_t result;
	struct stat statbuf;
	bool seen_bind_under_new_root = false;

	if (config->euid != 0) /* TODO: && !HAS_CAP(SYS_CHROOT) */
		return from_sigsys ? -EPERM : 0;

	if (from_sigsys) {
		/* Fetch reg early and from CURRENT RegVersion
		 * if this call is from SIGSYS handler.  */
		input = peek_reg(tracee, CURRENT, SYSARG_1);

		/* Set default error if we're here due to SIGSYS.  */
		poke_reg(tracee, SYSARG_RESULT, -EPERM);
	} else {
		/* Override only permission errors.
		 * (If we're here due to SIGSYS we don't check that
		 * we know syscall couldn't even be made.  */
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int) result != -EPERM)
			return 0;

		/* The path the tracee passed, not the translated one.  */
		input = peek_reg(tracee, ORIGINAL, SYSARG_1);
	}

	/* Get chroot target guest path.  */
	status = read_path(tracee, path_guest, input);
	if (status < 0)
		return status;

	/* The kernel rejects an empty path, which is checked only here
	 * when the syscall couldn't even be made (SIGSYS).  */
	if (path_guest[0] == '\0')
		return -ENOENT;

	/* Get chroot target path translated to host.  */
	if (!from_sigsys) {
		input = peek_reg(tracee, MODIFIED, SYSARG_1);

		status = read_path(tracee, path, input);
	} else {
		status = translate_path(tracee, path, AT_FDCWD, path_guest, true);
	}

	if (status < 0)
		return status;

	if (realpath(path, path_host_absolute) == NULL)
		return -errno;

	/* Handle "new rootfs == current rootfs" case.  */
	status = compare_paths(get_root(tracee), path_host_absolute);
	if (status == PATHS_ARE_EQUAL) {
		/* Force success.  */
		if (from_sigsys) return 1;
		poke_reg(tracee, SYSARG_RESULT, 0);
		return 0;
	}

	/* Validate chroot target.  */
	status = stat(path_host_absolute, &statbuf);
	if (status < 0)
		return -errno;

	if (!S_ISDIR(statbuf.st_mode))
		return -ENOTDIR;

	/* Canonicalize the guest path, as for the guest paths of the
	 * bindings, so that it compares with them (whether it's relative,
	 * holds "..", or goes through a symbolic link).  */
	status = guest_canonicalize(tracee, path_guest, path);
	if (status < 0)
		return status;
	strcpy(path_guest, path);

	/* Check if chroot target has bind mounts inside.
	 * (Those are not supported currently).  */
	Binding *binding;
	for (binding = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
	     binding != (void *) tracee->fs->bindings.guest;
	     binding = CIRCLEQ_NEXT(binding, link.guest)) {

		bool is_guest_root = binding == CIRCLEQ_LAST(tracee->fs->bindings.guest);

		if (!is_guest_root && compare_paths(path_guest, binding->guest.path) == PATH1_IS_PREFIX) {
			seen_bind_under_new_root = true;
			break;
		}
	}

	/* Change tracee root binding if supported.  */
	if (!seen_bind_under_new_root) {
		FileSystemNameSpace *previous;

		/* Save current dir.  */
		status = translate_path(tracee, path, AT_FDCWD, tracee->fs->cwd, true);
		if (status < 0)
			return status;

		/* Replace tracee bindings.  The previous ones are released
		 * last: the new root may be a tmpfs only these hold (see
		 * insort_tmpfs_binding()), and they are kept on error.  */
		previous = tracee->fs;
		tracee->fs = talloc_zero(tracee, FileSystemNameSpace);
		if (   tracee->fs == NULL
		    || new_binding(tracee, path_host_absolute, "/", true) == NULL
		    || initialize_bindings(tracee) < 0) {
			TALLOC_FREE(tracee->fs);
			tracee->fs = previous;
			return -ENOMEM;
		}
		talloc_unlink(tracee, previous);

		/* Restore current dir.  */
		status = detranslate_path(tracee, path, NULL);
		if (status <= 0) {
			tracee->fs->cwd = talloc_strdup(tracee->fs, "/");
		} else {
			tracee->fs->cwd = talloc_strdup(tracee->fs, path);
		}

		/* Force success.  */
		if (from_sigsys) return 1;
		poke_reg(tracee, SYSARG_RESULT, 0);
		return 0;
	}

	/* Unsupported chroot() variant.  */
	return from_sigsys ? -ENOSYS : 0;
}
