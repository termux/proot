#include <errno.h>       /* E*, */

#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "extension/fake_id0/chroot.h"

int handle_chroot_exit_end(Tracee *tracee, Config *config) {
	char path[PATH_MAX];
	char path_translated[PATH_MAX];
	char path_translated_absolute[PATH_MAX];
	char root_translated[PATH_MAX];
	char root_translated_absolute[PATH_MAX];
	word_t input;
	int status;
	word_t result;

	if (config->euid != 0) /* TODO: && !HAS_CAP(SYS_CHROOT) */
		return 0;

	/* Override only permission errors.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result != -EPERM)
		return 0;

	input = peek_reg(tracee, MODIFIED, SYSARG_1);

	status = read_path(tracee, path, input);
	if (status < 0)
		return status;
	status = translate_path(tracee, path_translated, AT_FDCWD, path, false);
	if (status < 0)
		return status;
	realpath(path_translated, path_translated_absolute);

	status = translate_path(tracee, root_translated, AT_FDCWD, get_root(tracee), false);
	if (status < 0)
		return status;
	realpath(root_translated, root_translated_absolute);

	/* Only "new rootfs == current rootfs" is supported yet.  */
	status = compare_paths(root_translated_absolute, path_translated_absolute);
	if (status != PATHS_ARE_EQUAL)
		return 0;

	/* Force success.  */
	poke_reg(tracee, SYSARG_RESULT, 0);
	return 0;
}
