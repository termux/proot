#include <errno.h>     /* E*, */
#include <signal.h>    /* SIGSYS, */
#include <unistd.h>    /* getpgid, */
#include <utime.h>     /* utimbuf, */
#include <sys/vfs.h>   /* statfs64 */
#include <string.h>    /* memset   */
#include <linux/net.h> /* SYS_SENDMMSG */
#include <assert.h>    /* assert(3), */

#include "extension/extension.h"
#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "path/path.h"

static int handle_seccomp_event_common(Tracee *tracee);

/**
 * Restart syscall that caused seccomp event
 * after changing it in tracee registers
 *
 * Syscall that will be restarted will be translated by proot
 * so SIGSYS handler sees untranslated paths and should leave
 * them untranslated.
 */
static void restart_syscall_after_seccomp(Tracee* tracee) {
	word_t instr_pointer;

	/* Enable restore regs at end of replaced call.  */
	tracee->restore_original_regs_after_seccomp_event = true;
	tracee->restart_how = PTRACE_SYSCALL;

	/* Move the instruction pointer back to the original trap */
	instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
	poke_reg(tracee, INSTR_POINTER, instr_pointer - get_systrap_size(tracee));

	/* X86 usually uses orig_rax when selecting syscall,
	 * but as this code is happening outside syscall handler
	 * we need to copy orig_eax back to eax.  */
#if defined(ARCH_X86_64)
	tracee->_regs[CURRENT].rax = tracee->_regs[CURRENT].orig_rax;
#elif defined(ARCH_X86)
	tracee->_regs[CURRENT].eax = tracee->_regs[CURRENT].orig_eax;
#endif

	/* Write registers. (Omiting special sysnum logic as we're not during syscall
	 * execution, but we're queueing new syscall to be called) */
	push_specific_regs(tracee, false);
}

/**
 * Set specified result (negative for errno) and do not restart syscall.
 */
static void set_result_after_seccomp(Tracee *tracee, word_t result) {
	poke_reg(tracee, SYSARG_RESULT, result);
	push_specific_regs(tracee, false);
}

/**
 * Handle SIGSYS signal that was caused by system seccomp policy.
 *
 * Return 0 to swallow signal or SIGSYS to deliver it to process.
 */
int handle_seccomp_event(Tracee* tracee)
{
	int ret;

	/* Reset status so next SIGTRAP | 0x80 is
	 * recognized as syscall entry.  */
	tracee->status = 0;

	/* Registers are never restored at this stage as they weren't saved.  */
	tracee->restore_original_regs = false;

	/* Fetch registers.  */
	ret = fetch_regs(tracee);
	if (ret != 0) {
		VERBOSE(tracee, 1, "Couldn't fetch regs on seccomp SIGSYS");
		return SIGSYS;
	}

	/* Save regs so they can be restored at end of replaced call.  */
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	/* X86 uses orig_rax when selecting syscall,
	 * however at this point we are after syscall has been rejected
	 * and orig_rax was reset to -1.  */
#if defined(ARCH_X86_64)
	tracee->_regs[CURRENT].orig_rax = tracee->_regs[CURRENT].rax;
#elif defined(ARCH_X86)
	tracee->_regs[CURRENT].orig_eax = tracee->_regs[CURRENT].eax;
#endif

	print_current_regs(tracee, 3, "seccomp SIGSYS");

	return handle_seccomp_event_common(tracee);
}

void fix_and_restart_enosys_syscall(Tracee* tracee)
{
	/* Reset tracee state so we're not handling syscall exit */
	tracee->status = 0;
	tracee->restore_original_regs = false;

	/* Restore and save original registers */
	memcpy(&tracee->_regs[CURRENT], &tracee->_regs[ORIGINAL], sizeof(tracee->_regs[CURRENT]));
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	handle_seccomp_event_common(tracee);
}

static int handle_seccomp_event_common(Tracee *tracee)
{
	int ret;
	int status;
	Sysnum sysnum = get_sysnum(tracee, CURRENT);

	sysnum = get_sysnum(tracee, CURRENT);

	status = notify_extensions(tracee, SIGSYS_OCC, 0, 0);
	if (status < 0) {
		VERBOSE(tracee, 4, "SIGSYS errored out when being handled by an extension");
		set_result_after_seccomp(tracee, status);
		return 0;
	}
	if (status == 1) {
		VERBOSE(tracee, 4, "SIGSYS fully handled by an extension");
		set_result_after_seccomp(tracee, 0);
		return 0;
	}

	switch (sysnum) {
	case PR_open:
		set_sysnum(tracee, PR_openat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_accept:
		set_sysnum(tracee, PR_accept4);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_setgroups:
	case PR_setgroups32:
		set_result_after_seccomp(tracee, 0);
		break;

	case PR_getpgrp:
		/* Query value with getpgid and set it as result.  */
		set_result_after_seccomp(tracee, getpgid(tracee->pid));
		break;

	case PR_symlink:
		set_sysnum(tracee, PR_symlinkat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_link:
		set_sysnum(tracee, PR_linkat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, AT_FDCWD);
		poke_reg(tracee, SYSARG_5, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_chmod:
		set_sysnum(tracee, PR_fchmodat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_chown:
	case PR_lchown:
	case PR_chown32:
	case PR_lchown32:
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
		break;

	case PR_rmdir:
		set_sysnum(tracee, PR_unlinkat);
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, AT_REMOVEDIR);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_send:
		set_sysnum(tracee, PR_sendto);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_recv:
		set_sysnum(tracee, PR_recvfrom);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_waitpid:
		set_sysnum(tracee, PR_wait4);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_statfs:
	{
		int size;
		int status;
		char path[PATH_MAX];
		char original[PATH_MAX];
		char devshm_path[PATH_MAX];
		struct statfs64 my_statfs64;
		struct compat_statfs my_statfs;
		size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_1), PATH_MAX);
		if (size < 0) {
			set_result_after_seccomp(tracee, size);
			break;
		}
		if (size >= PATH_MAX) { 
			set_result_after_seccomp(tracee, -ENAMETOOLONG);
			break;
		}
            	translate_path(tracee, path, AT_FDCWD, original, true);
		errno = 0;
		status = statfs64(path, &my_statfs64); 
		if (errno != 0) {
			set_result_after_seccomp(tracee, -errno);
			break;
		}

		/* Fake /dev/shm being tmpfs, see statfs handler in syscall/exit.c */
		if (translate_path(tracee, devshm_path, AT_FDCWD, "/dev/shm", true) >= 0) {
			Comparison comparison = compare_paths(devshm_path, path);
			if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
				my_statfs64.f_type = 0x01021994;
			}
		}

		if ((my_statfs64.f_blocks | my_statfs64.f_bfree | my_statfs64.f_bavail |
     		     my_statfs64.f_bsize | my_statfs64.f_frsize | my_statfs64.f_files | 
		     my_statfs64.f_ffree) & 0xffffffff00000000ULL) { 
			set_result_after_seccomp(tracee, -EOVERFLOW);
			break;
		}
		my_statfs.f_type = my_statfs64.f_type;
		my_statfs.f_bsize = my_statfs64.f_bsize;
		my_statfs.f_blocks = my_statfs64.f_blocks;
		my_statfs.f_bfree = my_statfs64.f_bfree;
		my_statfs.f_bavail = my_statfs64.f_bavail;
		my_statfs.f_files = my_statfs64.f_files;
		my_statfs.f_ffree = my_statfs64.f_ffree;
		my_statfs.f_fsid = my_statfs64.f_fsid;
		my_statfs.f_namelen = my_statfs64.f_namelen;
		my_statfs.f_frsize = my_statfs64.f_frsize;
		my_statfs.f_flags = my_statfs64.f_flags;
		memset(my_statfs.f_spare, 0, sizeof(my_statfs.f_spare));
                write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_2), &my_statfs, sizeof(struct compat_statfs));

		set_result_after_seccomp(tracee, 0);
		break;
	}

	case PR_utimes:
	{
		/* int utimes(const char *filename, const struct timeval times[2]);
		 *
		 * convert to:
		 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);  */
		struct timeval times[2];
		struct timespec timens[2];

		set_sysnum(tracee, PR_utimensat);
		if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
			ret = read_data(tracee, times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
			timens[0].tv_sec = (time_t)times[0].tv_sec;
			timens[0].tv_nsec = (long)times[0].tv_usec * 1000;
			timens[1].tv_sec = (time_t)times[1].tv_sec;
			timens[1].tv_nsec = (long)times[1].tv_usec * 1000;
			ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
		}
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_utime:
	{
		/* int utime(const char *filename, const struct utimbuf *times);
		 *
		 * convert to:
		 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);  */
		struct utimbuf times;
		struct timespec timens[2];

		set_sysnum(tracee, PR_utimensat);
		if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
			ret = read_data(tracee, &times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
			timens[0].tv_sec = (time_t)times.actime;
			timens[0].tv_nsec = 0;
			timens[1].tv_sec = (time_t)times.modtime;
			timens[1].tv_nsec = 0;
			ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
		}
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;
	}

#if defined(ARCH_X86) || defined(ARCH_X86_64)
	case PR_sendmmsg:
	{
		/* Convert direct sendmmsg syscall to socketcall.
		 * This affects only 32-bit x86, in other archs
		 * bionic doesn't use socketcall() for sendmmsg.  */
		size_t arg_size = sizeof_word(tracee);
		assert(arg_size <= sizeof(word_t));
		byte_t args[arg_size * 4];
		memset(args, 0, arg_size * 4);
		*(word_t*)(args) = peek_reg(tracee, CURRENT, SYSARG_1);
		*(word_t*)(args + arg_size) = peek_reg(tracee, CURRENT, SYSARG_2);
		*(word_t*)(args + 2 * arg_size) = peek_reg(tracee, CURRENT, SYSARG_3);
		*(word_t*)(args + 3 * arg_size) = peek_reg(tracee, CURRENT, SYSARG_4);
		word_t tracee_args = alloc_mem(tracee, arg_size * 4);
		write_data(tracee, tracee_args, args, arg_size * 4);
		set_sysnum(tracee, PR_socketcall);
		poke_reg(tracee, SYSARG_1, SYS_SENDMMSG);
		poke_reg(tracee, SYSARG_2, tracee_args);
		restart_syscall_after_seccomp(tracee);
		break;
	}
#endif

	case PR_set_robust_list:
	default:
		/* Set errno to -ENOSYS */
		set_result_after_seccomp(tracee, -ENOSYS);
	}

	return 0;
}
