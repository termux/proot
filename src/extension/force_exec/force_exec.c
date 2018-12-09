#include <errno.h>     /* E*, */
#include <sys/mman.h>  /* PROT_*, MAP_* */

#include "extension/extension.h"

static int force_exec_handle_sysexit_end(Tracee *tracee)
{
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);

	switch (sysnum) {
	case PR_mmap:
	case PR_mmap2: {
		word_t ret = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		word_t prot = peek_reg(tracee, ORIGINAL, SYSARG_3);
		word_t flags = peek_reg(tracee, ORIGINAL, SYSARG_4);
		if (
				ret == ((word_t)-EACCES) &&
				prot == (PROT_READ | PROT_EXEC) &&
				(flags & (MAP_ANONYMOUS | MAP_FIXED)) == MAP_FIXED
				) {
			word_t addr = peek_reg(tracee, ORIGINAL, SYSARG_1);
			word_t len = peek_reg(tracee, ORIGINAL, SYSARG_2);
			word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_5);
			word_t offset = peek_reg(tracee, ORIGINAL, SYSARG_6);
			register_chained_syscall(
					tracee,
					sysnum,
					addr,
					len,
					PROT_READ | PROT_WRITE,
					flags | MAP_ANONYMOUS,
					-1,
					0
			);
			register_chained_syscall(
					tracee,
					PR_pread64,
					fd,
					addr,
					len,
					(sysnum == PR_mmap2 ? offset * 4096 : offset),
					0,
					0
			);
			register_chained_syscall(
					tracee,
					PR_mprotect,
					addr,
					len,
					PROT_READ | PROT_EXEC,
					0,
					0,
					0
			);
			force_chain_final_result(tracee, addr);
		}
		return 0;
	}
	default:
		return 0;
	}
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int force_exec_callback(Extension *extension, ExtensionEvent event,
				  intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		/* List of syscalls handled by this extensions.	 */
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_mmap,	   FILTER_SYSEXIT },
			{ PR_mmap2,		FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case SYSCALL_EXIT_END: {
		return force_exec_handle_sysexit_end(TRACEE(extension));
	}

	default:
		return 0;
	}
}
