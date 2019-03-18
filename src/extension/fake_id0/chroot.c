#include <errno.h>       /* E*, */

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "extension/fake_id0/chroot.h"

int handle_chroot_exit_end(Tracee *tracee, Config *config) {
	char path[PATH_MAX];
	char path_absolute[PATH_MAX];
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

	realpath(path, path_absolute);

	/* Only "new rootfs == current rootfs" is supported yet.  */
	status = compare_paths(get_root(tracee), path_absolute);
	if (status != PATHS_ARE_EQUAL)
		return 0;

	/* Force success.  */
	poke_reg(tracee, SYSARG_RESULT, 0);
	return 0;
}
