#include <errno.h>     /* E*, */
#include <signal.h>    /* SIGSYS, */
#include <unistd.h>    /* getpgid, */

#include "cli/note.h"
#include "syscall/chain.h"
#include "tracee/seccomp.h"


int handle_seccomp_event(Tracee* tracee) {

	word_t sysnum;
	int signal;
	word_t instr_pointer;

	signal = SIGSYS;

	int sigsys_fetch_status = fetch_regs(tracee);
	if (sigsys_fetch_status != 0) {
		VERBOSE(tracee, 1, "Couldn't fetch regs on seccomp SIGSYS");
		return signal;
	}
	print_current_regs(tracee, 3, "seccomp SIGSYS");
	tracee->restore_original_regs = false;

	sysnum = get_sysnum(tracee, CURRENT);

	switch (sysnum) {
	case PR_accept:
		set_sysnum(tracee, PR_accept4);
		poke_reg(tracee, SYSARG_4, 0);

		/* Move the instruction pointer back to the original trap */
		instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
		poke_reg(tracee, INSTR_POINTER, instr_pointer - SYSTRAP_SIZE);
		/* Break as usual on entry to syscall */
		tracee->restart_how = PTRACE_SYSCALL;
		push_specific_regs(tracee, true);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_getpgrp:
		/* Query value with getpgid and set it as result.  */
		poke_reg(tracee, SYSARG_RESULT, getpgid(tracee->pid));
		push_specific_regs(tracee, false);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_set_robust_list:
	default:
		/* Set errno to -ENOSYS */
		poke_reg(tracee, SYSARG_RESULT, -ENOSYS);
		push_specific_regs(tracee, false);

		/* Swallow signal */
		signal = 0;
		break;
	}

	/* Reset status so next SIGTRAP | 0x80 is
	 * recognized as syscall entry */
	tracee->status = 0;

	return signal;
}
