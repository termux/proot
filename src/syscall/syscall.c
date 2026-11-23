/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <assert.h>      /* assert(3), */
#include <limits.h>      /* PATH_MAX, */
#include <string.h>      /* strlen(3), */
#include <errno.h>       /* errno(3), E* */

#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"

/**
 * Copy in @path a C string (PATH_MAX bytes max.) from the @tracee's
 * memory address space pointed to by the @reg argument of the
 * current syscall.  This function returns -errno if an error occured,
 * otherwise it returns the size in bytes put into the @path.
 */
int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
	int size;
	word_t src;

	src = peek_reg(tracee, CURRENT, reg);

	/* Check if the parameter is not NULL. Technically we should
	 * not return an -EFAULT for this special value since it is
	 * allowed for some syscall, utimensat(2) for instance. */
	if (src == 0) {
		path[0] = '\0';
		return 0;
	}

	/* Get the path from the tracee's memory space. */
	size = read_path(tracee, path, src);
	if (size < 0)
		return size;

	path[size] = '\0';
	return size;
}

/**
 * Copy @size bytes of the data pointed to by @tracer_ptr into a
 * @tracee's memory block and make the @reg argument of the current
 * syscall points to this new block.  This function returns -errno if
 * an error occured, otherwise 0.
 */
int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg)
{
	word_t tracee_ptr;
	int status;

	/* Allocate space into the tracee's memory to host the new data. */
	tracee_ptr = alloc_mem(tracee, size);
	if (tracee_ptr == 0)
		return -EFAULT;

	/* Copy the new data into the previously allocated space. */
	status = write_data(tracee, tracee_ptr, tracer_ptr, size);
	if (status < 0)
		return status;

	/* Make this argument point to the new data. */
	poke_reg(tracee, reg, tracee_ptr);

	return 0;
}

/**
 * Copy @path to a @tracee's memory block and make the @reg argument
 * of the current syscall points to this new block.  This function
 * returns -errno if an error occured, otherwise 0.
 */
int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg)
{
	return set_sysarg_data(tracee, path, strlen(path) + 1, reg);
}

/**
 * Tell whether the syscall number the @tracee holds in @version is the
 * avoider, ie. whether PRoot replaced the syscall the tracee asked for
 * with a no-op in order to answer it itself.
 */
bool is_voided_syscall(const Tracee *tracee, RegVersion version)
{
	word_t avoider = SYSCALL_AVOIDER;

#if defined(ARCH_ARM64) || defined(ARCH_X86_64)
	if (is_32on64_mode(tracee))
		avoider &= 0xFFFFFFFF;
#endif

	return peek_reg(tracee, version, SYSARG_NUM) == avoider
	    && peek_reg(tracee, ORIGINAL, SYSARG_NUM) != avoider;
}

/**
 * Tell whether the host kernel cancels a syscall PRoot voided instead
 * of letting the avoider it was replaced with run.  A tracer that
 * turns a syscall number negative cancels the call: the kernel neither
 * executes it -- so the result PRoot poked at the enter stage stays
 * untouched -- nor, on kernels which evaluate seccomp before the ptrace
 * sysenter stop, reports that stop.  ARM's avoider is tuxcall(2),
 * number 222, which is neither negative nor out of range: it really
 * reaches the kernel.
 */
static bool kernel_cancels_voided_syscall(void)
{
	/* A 32-bit tracee running on a 64-bit kernel needs no special
	 * case here: the avoider reaches that kernel truncated to its
	 * 32 least significant bits, which are read back as a negative
	 * syscall number just the same.  */
	return (long) SYSCALL_AVOIDER < 0;
}

void translate_syscall(Tracee *tracee)
{
	const bool is_enter_stage = IS_IN_SYSENTER(tracee);
	int status;

	assert(tracee->exe != NULL);

	if (!tracee->regs_fetched_at_stop) {
		status = fetch_regs(tracee);
		if (status < 0)
			return;
	}
	tracee->regs_fetched_at_stop = false;

	int suppressed_syscall_status = 0;

	if (is_enter_stage) {
		/* Never restore original register values at the end
		 * of this stage.  */
		tracee->restore_original_regs = false;
		tracee->voided_syscall_cancelled = false;

		print_current_regs(tracee, 3, "sysenter start");

#ifdef HAS_POKEDATA_WORKAROUND
		/* In case of pokedata workaround has cancelled real enter
		 * of syscall we've enqueued start of syscall again
		 * so we won't translate it here again.  */
		if (tracee->pokedata_workaround_relaunched_syscall) {
			tracee->pokedata_workaround_relaunched_syscall = false;
			tracee->status = 1;
			tracee->restart_how = PTRACE_SYSCALL;
			return;
		}
#endif

		/* Translate the syscall only if it was actually
		 * requested by the tracee, it is not a syscall
		 * chained by PRoot.  */
		if (tracee->chain.syscalls == NULL) {
			save_current_regs(tracee, ORIGINAL);
			status = translate_syscall_enter(tracee);
			save_current_regs(tracee, MODIFIED);
		}
		else {
			if (tracee->chain.sysnum_workaround_state != SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL) {
				status = notify_extensions(tracee, SYSCALL_CHAINED_ENTER, 0, 0);
			}
			tracee->restart_how = PTRACE_SYSCALL;
		}

		/* Remember the tracee status for the "exit" stage and
		 * avoid the actual syscall if an error was reported
		 * by the translation/extension. */
		if (status < 0) {
			set_sysnum(tracee, PR_void);
			poke_reg(tracee, SYSARG_RESULT, (word_t) status);
			tracee->status = status;
#if defined(ARCH_ARM_EABI)
			tracee->restart_how = PTRACE_SYSCALL;
#endif
		}
		else {
			tracee->status = 1;

			/* PRoot answers some syscalls itself: their number was
			 * replaced with the avoider and their result poked
			 * just now, at the enter stage.  Whenever that avoider
			 * syscall reaches the host kernel, the kernel is free
			 * to overwrite the result register -- with -ENOSYS when
			 * it doesn't implement the number, or with the
			 * syscall's own first argument when an outer seccomp
			 * policy traps it, since SECCOMP_RET_TRAP rolls the
			 * registers back to their pre-syscall values (Android
			 * sandboxes do exactly that to the in-range number ARM
			 * uses as the avoider).  Only translate_syscall_exit()
			 * puts the faked result back, so make sure the exit
			 * stage is reached; syscalls whose seccomp filter entry
			 * already asks for it just keep what they had.  An
			 * avoider the kernel cancels needs none of this, and
			 * asking for a stop the kernel doesn't report there
			 * would desynchronize the event loop.  */
			if (is_voided_syscall(tracee, CURRENT) && !kernel_cancels_voided_syscall()) {
				tracee->sysexit_pending = true;
				tracee->restart_how = PTRACE_SYSCALL;
			}
		}

#ifdef HAS_POKEDATA_WORKAROUND
		if (tracee->pokedata_workaround_cancelled_syscall) {
			tracee->pokedata_workaround_cancelled_syscall = false;
			tracee->pokedata_workaround_relaunched_syscall = true;
			tracee->restart_how = PTRACE_SYSCALL;
			tracee->status = 0;
			poke_reg(tracee, INSTR_POINTER, peek_reg(tracee, CURRENT, INSTR_POINTER) - SYSTRAP_SIZE);
			push_specific_regs(tracee, false);
			return;
		}
#endif

		/* Restore tracee's stack pointer now if it won't hit
		 * the sysexit stage (i.e. when seccomp is enabled and
		 * there's nothing else to do).  */
		if (tracee->restart_how == PTRACE_CONT) {
			suppressed_syscall_status = tracee->status;
			tracee->status = 0;
			poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, STACK_POINTER));
		}
	}
	else {
		/* By default, restore original register values at the
		 * end of this stage.  */
		tracee->restore_original_regs = true;

#ifdef HAS_POKEDATA_WORKAROUND
		/* This is exit from syscall that was cancelled
		 * by pokedata workaround - ignore.  */
		if (tracee->pokedata_workaround_relaunched_syscall)
		{
			return;
		}
#endif

		print_current_regs(tracee, 5, "sysexit start");

		/* Translate the syscall only if it was actually
		 * requested by the tracee, it is not a syscall
		 * chained by PRoot.  */
		if (tracee->chain.syscalls == NULL || tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_INACTIVE;
			translate_syscall_exit(tracee);
		}
		else if (tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL;
		}
		else
			(void) notify_extensions(tracee, SYSCALL_CHAINED_EXIT, 0, 0);

		/* Reset the tracee's status. */
		tracee->status = 0;
#ifdef HAS_POKEDATA_WORKAROUND
		tracee->pokedata_workaround_cancelled_syscall = false;
#endif

		/* Insert the next chained syscall, if any.  */
		if (tracee->chain.syscalls != NULL)
			chain_next_syscall(tracee);
	}

	bool override_sysnum = is_enter_stage && tracee->chain.syscalls == NULL;
	int push_regs_status = push_specific_regs(tracee, override_sysnum);

	/* Whether the syscall number PRoot chose is the one the tracee
	 * is really going to enter the kernel with.  */
	const bool sysnum_pushed = override_sysnum && push_regs_status == 0;

	/* Handle inability to change syscall number */
	if (push_regs_status < 0 && override_sysnum) {
		word_t orig_sysnum = peek_reg(tracee, ORIGINAL, SYSARG_NUM);
		word_t current_sysnum = peek_reg(tracee, CURRENT, SYSARG_NUM);
		print_current_regs(tracee, 4, "pre_push");
		if (orig_sysnum != current_sysnum) {
			/* Restart current syscall as chained */
			if (current_sysnum != SYSCALL_AVOIDER) {
				restart_current_syscall_as_chained(tracee);
			} else if (suppressed_syscall_status) {
				/* If we've decided to fail this syscall
				 * by setting it to no-op and continuing, but turns out
				 * that we can't just make syscall nop, restore tracee->status
				 * and intercept syscall exit */
				tracee->status = suppressed_syscall_status;
				tracee->restart_how = PTRACE_SYSCALL;
			}

			/* Set syscall arguments to make it fail
			 * TODO: More reliable way to make invalid arguments
			 * For most syscalls we set all args to -1
			 * Hoping there is among them invalid request/address/fd/value that will make syscall fail */
			poke_reg(tracee, SYSARG_1, -1);
			poke_reg(tracee, SYSARG_2, -1);
			poke_reg(tracee, SYSARG_3, -1);
			poke_reg(tracee, SYSARG_4, -1);
			poke_reg(tracee, SYSARG_5, -1);
			poke_reg(tracee, SYSARG_6, -1);

			if (get_sysnum(tracee, ORIGINAL) == PR_brk) {
				/* For brk() we pass 0 as first arg; this is used to query value without changing it */
				poke_reg(tracee, SYSARG_1, 0);
			}

			/* Push regs again without changing syscall */
			push_regs_status = push_specific_regs(tracee, false);
			if (push_regs_status != 0) {
				note(tracee, WARNING, SYSTEM, "can't set tracee registers in workaround");
			}
		}
	}

	if (is_enter_stage) {
		/* Tell the event loop that the host kernel is about to
		 * drop this syscall on the floor, hence that it reports
		 * no sysenter stop for it.  The avoider must have made
		 * it to the tracee for that: when the syscall number
		 * can't be changed, the fallback above lets the original
		 * syscall run with invalid arguments instead.  */
		tracee->voided_syscall_cancelled = sysnum_pushed
						&& kernel_cancels_voided_syscall()
						&& is_voided_syscall(tracee, CURRENT);

		print_current_regs(tracee, 5, "sysenter end" );
	}
	else
		print_current_regs(tracee, 4, "sysexit end");
}
