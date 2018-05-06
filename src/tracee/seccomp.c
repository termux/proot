#include <errno.h>     /* E*, */
#include <signal.h>    /* SIGSYS, */
#include <unistd.h>    /* getpgid, */

#include "cli/note.h"
#include "syscall/chain.h"
#include "tracee/seccomp.h"

/**
 * Prepare tracee to restart modified syscall after seccomp SIGSYS
 * signal.
 *
 * This function prepares registers to restore and must be called
 * before modyfying them.
 *
 * restart_syscall_after_seccomp() must be called after syscall change.
 * (And if that function won't be called this one shoudn,t be as well.)
 */
static void prepare_restart_syscall_after_seccomp(Tracee* tracee) {
	/* Prepare to restore regs at end of replaced call.  */
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);
	tracee->restore_original_regs_after_seccomp_event = true;
	tracee->restart_how = PTRACE_SYSCALL;
}

static void restart_syscall_after_seccomp(Tracee* tracee) {
	word_t instr_pointer;
	word_t systrap_size = SYSTRAP_SIZE;

	/* Move the instruction pointer back to the original trap */
	instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
#if defined(ARCH_ARM_EABI)
	/* On ARM thumb mode systrap size is 2 */
	if (tracee->_regs[CURRENT].ARM_cpsr & PSR_T_BIT) {
		systrap_size = 2;
	}
#endif
	poke_reg(tracee, INSTR_POINTER, instr_pointer - systrap_size);

	/* Write registers. (Omiting special sysnum logic as we're not during syscall
	 * execution, but we're queueing new syscall to be called) */
	push_specific_regs(tracee, false);
}

int handle_seccomp_event(Tracee* tracee) {

	Sysnum sysnum;
	int signal;

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
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_accept4);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);

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

	case PR_symlink:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_symlinkat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_link:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_linkat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, AT_FDCWD);
		poke_reg(tracee, SYSARG_5, 0);
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_chmod:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_fchmodat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_chown:
	case PR_lchown:
	case PR_chown32:
	case PR_lchown32:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_fchownat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		if (sysnum == PR_lchown || sysnum == PR_lchown32) {
			poke_reg(tracee, SYSARG_5, AT_SYMLINK_NOFOLLOW);
		} else {
			poke_reg(tracee, SYSARG_5, 0);
		}
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_rmdir:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_unlinkat);
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, AT_REMOVEDIR);
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_send:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_sendto);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);

		/* Swallow signal */
		signal = 0;
		break;

	case PR_recv:
		prepare_restart_syscall_after_seccomp(tracee);
		set_sysnum(tracee, PR_recvfrom);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);

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
