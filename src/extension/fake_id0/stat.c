#include <linux/limits.h>
#include <sys/types.h>   /* uid_t, gid_t, get*id(2), */
#include <unistd.h>      /* get*id(2),  */
#include <assert.h>      /* assert(3), */

#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "extension/fake_id0/stat.h"

/** Convert fstat and fstat64 to readlink
 *  this is so we can get the path associated with /proc/pid#/fd/fd#
 */
int handle_stat_enter_end(Tracee *tracee, Reg fd_sysarg) {
	char path[PATH_MAX];
	char link_path[64];
	word_t link_address;
	word_t path_address;

	set_sysnum(tracee, PR_readlinkat);
	snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", tracee->pid, (int)peek_reg(tracee, CURRENT, fd_sysarg));
	link_address = alloc_mem(tracee, sizeof(link_path));
	path_address = alloc_mem(tracee, sizeof(path));
	write_data(tracee, link_address, link_path, sizeof(link_path));
	poke_reg(tracee, SYSARG_1, AT_FDCWD);	
	poke_reg(tracee, SYSARG_2, link_address);	
	poke_reg(tracee, SYSARG_3, path_address);	
	poke_reg(tracee, SYSARG_4, sizeof(path));	
	return 0;
}

int handle_stat_exit_end(Tracee *tracee, Config *config, Reg stat_sysarg) {
	word_t address;
	uid_t uid;
	gid_t gid;
	word_t result;

	/* Override only if it succeed.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0)
		return 0;

	address = peek_reg(tracee, ORIGINAL, stat_sysarg);

	/* Sanity checks.  */
	assert(__builtin_types_compatible_p(uid_t, uint32_t));
	assert(__builtin_types_compatible_p(gid_t, uint32_t));

	/* Get the uid & gid values from the 'stat' structure.  */
	uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee));
	if (errno != 0)
		uid = 0; /* Not fatal.  */

	gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee));
	if (errno != 0)
		gid = 0; /* Not fatal.  */

	/* Override only if the file is owned by the current user.
	 * Errors are not fatal here.  */
	if (uid == getuid())
		poke_uint32(tracee, address + offsetof_stat_uid(tracee), config->suid);

	if (gid == getgid())
		poke_uint32(tracee, address + offsetof_stat_gid(tracee), config->sgid);

	return 0;
}
