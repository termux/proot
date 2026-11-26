#include <errno.h>          /* E*, */
#include <fcntl.h>          /* AT_*, */
#include <string.h>         /* strncmp(3), */
#include <unistd.h>         /* syscall(2), close(2), */
#include <sys/syscall.h>    /* __NR_statx, __NR_pidfd_*, */
#include <sys/sysmacros.h>  /* major, minor, */

#include "tracee/statx.h"
#include "tracee/mem.h"
#include "tracee/reg.h"

int handle_statx_syscall(Tracee *tracee, bool from_sigsys) {
	RegVersion regVersion = from_sigsys ? CURRENT : ORIGINAL;
	struct statx_syscall_state state = {};
	char guest_path[PATH_MAX] = {};
	struct stat stat_buf = {};
	bool do_fstat = false;

	/* The kernel's answer stands, unless statx() itself is missing:
	 * ENOSYS before Linux 4.11, or EPERM when a seccomp policy
	 * denies it (container runtimes, systemd), as Rust's standard
	 * library assumes too -- PRoot gets to see this latter only when
	 * it runs without seccomp, otherwise the policy outranks the
	 * filter of PRoot.  Then it is emulated with [l]stat() below.
	 * Any other error is about the path or the arguments: [l]stat()
	 * would only report ENOENT once again -- after the cost of a
	 * second path translation -- and it would turn EINVAL for
	 * unknown flags or mask bits into a made-up success.  */
	if (!from_sigsys) {
		int result = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);

		if (result < 0 && result != -ENOSYS && result != -EPERM)
			return result;
	}

	/* When the kernel performed this statx() successfully, the
	 * host path it looked at is the one the enter stage put in
	 * place of the guest path: read it back rather than translating
	 * the guest path once again.  Otherwise statx() is emulated
	 * below, which requires a fresh translation: permissions that
	 * fake_id0 overrode during the enter stage are restored by
	 * now.  */
	bool kernel_succeeded = !from_sigsys && peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0;

	/* Read arguments and translate path */
	word_t flags = peek_reg(tracee, regVersion, SYSARG_3);
	bool do_lstat = ((flags & AT_SYMLINK_NOFOLLOW) != 0);
	word_t mask = peek_reg(tracee, regVersion, SYSARG_4);
	int status = read_string(tracee, guest_path, peek_reg(tracee, regVersion, SYSARG_2), PATH_MAX);
	if (status < 0) {
		return status;
	}

	word_t dirfd = peek_reg(tracee, regVersion, SYSARG_1);
	if (status == 0) {
		return -EFAULT;
	}
	if (status == 1) {
		if ((flags & AT_EMPTY_PATH) == 0) {
			return -ENOENT;
		}
		/* The empty path names the cwd, which is emulated: the
		 * guest one, not the tracee's actual cwd on the host.  */
		if ((int) dirfd == AT_FDCWD) {
			if (kernel_succeeded)
				status = read_path(tracee, state.host_path, peek_reg(tracee, MODIFIED, SYSARG_2));
			else
				status = translate_path(tracee, state.host_path, AT_FDCWD, ".", !do_lstat);
		} else {
			status = readlink_proc_pid_fd(tracee->pid, dirfd, state.host_path);
			do_fstat = true;
		}
	} else {
		if (status >= PATH_MAX) {
			return -ENAMETOOLONG;
		}
		if (kernel_succeeded)
			status = read_path(tracee, state.host_path, peek_reg(tracee, MODIFIED, SYSARG_2));
		else
			status = translate_path(tracee, state.host_path, dirfd, guest_path, !do_lstat);
	}
	if (status < 0) {
		return status;
	}

	if (!kernel_succeeded) {
		/* Call [l]stat() on translated path */
		if (do_fstat) {
			char link[32] = {}; /* 32 > sizeof("/proc//cwd") + sizeof(#ULONG_MAX) */
			snprintf(link, sizeof(link), "/proc/%d/fd/%d", tracee->pid, (int) dirfd);
			status = stat(link, &stat_buf);
		} else if (do_lstat) {
			status = lstat(state.host_path, &stat_buf);
		} else {
			status = stat(state.host_path, &stat_buf);
		}
		if (status < 0) {
			status = -errno;
			if (status >= 0) status = -EPERM;
			return status;
		}

		/* Translate results from stat to statx */
		state.statx_buf.stx_mask = (
			mask & (
				STATX_TYPE |
				STATX_MODE |
				STATX_NLINK |
				STATX_UID |
				STATX_GID |
				STATX_ATIME |
				STATX_MTIME |
				STATX_CTIME |
				STATX_INO |
				STATX_SIZE |
				STATX_BLOCKS |
				STATX_BTIME
			)
		);
		state.statx_buf.stx_blksize = stat_buf.st_blksize;
		if (mask & (STATX_TYPE | STATX_MODE)) {
			state.statx_buf.stx_mode = stat_buf.st_mode;
		}
		if (mask & STATX_NLINK) {
			state.statx_buf.stx_nlink = stat_buf.st_nlink;
		}
		if (mask & STATX_UID) {
			state.statx_buf.stx_uid = stat_buf.st_uid;
		}
		if (mask & STATX_GID) {
			state.statx_buf.stx_gid = stat_buf.st_gid;
		}
		if (mask & STATX_ATIME) {
			state.statx_buf.stx_atime.tv_sec = stat_buf.st_atim.tv_sec;
			state.statx_buf.stx_atime.tv_nsec = stat_buf.st_atim.tv_nsec;
		}
		if (mask & STATX_MTIME) {
			state.statx_buf.stx_mtime.tv_sec = stat_buf.st_mtim.tv_sec;
			state.statx_buf.stx_mtime.tv_nsec = stat_buf.st_mtim.tv_nsec;
		}
		if (mask & STATX_CTIME) {
			state.statx_buf.stx_ctime.tv_sec = stat_buf.st_ctim.tv_sec;
			state.statx_buf.stx_ctime.tv_nsec = stat_buf.st_ctim.tv_nsec;
		}
		if (mask & STATX_INO) {
			state.statx_buf.stx_ino = stat_buf.st_ino;
		}
		if (mask & STATX_SIZE) {
			state.statx_buf.stx_size = stat_buf.st_size;
		}
		if (mask & STATX_BLOCKS) {
			state.statx_buf.stx_blocks = stat_buf.st_blocks;
		}
		if (mask & STATX_BTIME) {
			// stat() doesn't expose this, take ctime
			state.statx_buf.stx_btime.tv_sec = stat_buf.st_ctim.tv_sec;
			state.statx_buf.stx_btime.tv_nsec = stat_buf.st_ctim.tv_nsec;
		}
		state.statx_buf.stx_rdev_major = major(stat_buf.st_rdev);
		state.statx_buf.stx_rdev_minor = minor(stat_buf.st_rdev);
		state.updated_stats = true;
	} else {
		status = read_data(tracee, &state.statx_buf, peek_reg(tracee, ORIGINAL, SYSARG_5), sizeof(struct statx));
		if (status < 0) {
			return status;
		}
	}

	/* Notify extensions */
	status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t) &state, 0);
	if (status < 0) {
		return status;
	}

	/* Return results to tracee */
	if (state.updated_stats) {
		status = write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_5), &state.statx_buf, sizeof(state.statx_buf));
		if (status < 0) {
			return status;
		}
	}
	return 0;
}

#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0x6000
#endif

/**
 * Answer statx(2) directly at the seccomp enter stop using the host path
 * already translated in CURRENT SYSARG_2 (or pidfd_getfd() for AT_EMPTY_PATH),
 * then invoke STATX_SYSCALL extensions and write the result back.  Returns 1
 * with *result set when answered, or 0 to fall back to the normal enter+exit
 * path (unusual flags, /proc paths, kernel lack of statx/pidfd_getfd, or host
 * errors other than ENOENT/ENOTDIR).
 */
int answer_statx_at_enter(Tracee *tracee, word_t *result)
{
#if defined(__NR_statx)
	struct statx_syscall_state state = {};
	const word_t dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
	const word_t flags = peek_reg(tracee, CURRENT, SYSARG_3);
	const word_t mask = peek_reg(tracee, CURRENT, SYSARG_4);
	int status;
	long rc;

	if ((flags & ~(word_t) (AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE)) != 0)
		return 0;

	status = read_string(tracee, state.host_path, peek_reg(tracee, CURRENT, SYSARG_2), PATH_MAX);
	if (status <= 0 || status >= PATH_MAX)
		return 0;

	if (status == 1) {
#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
		int pidfd, local;

		if ((flags & AT_EMPTY_PATH) == 0 || (int) dirfd < 0)
			return 0;
		if (readlink_proc_pid_fd(tracee->pid, (int) dirfd, state.host_path) < 0)
			return 0;
		pidfd = (int) syscall(__NR_pidfd_open, tracee->pid, 0);
		if (pidfd < 0)
			return 0;
		local = (int) syscall(__NR_pidfd_getfd, pidfd, (int) dirfd, 0);
		close(pidfd);
		if (local < 0)
			return 0;
		rc = syscall(__NR_statx, local, "", (int) (flags & (AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE)),
			     (unsigned int) mask, &state.statx_buf);
		close(local);
		if (rc != 0)
			return 0;
#else
		return 0;
#endif
	}
	else {
		if (state.host_path[0] != '/')
			return 0;
		if (strncmp(state.host_path, "/proc", 5) == 0 && (state.host_path[5] == '/' || state.host_path[5] == '\0'))
			return 0;
		rc = syscall(__NR_statx, AT_FDCWD, state.host_path,
			     (int) (flags & (AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE)),
			     (unsigned int) mask, &state.statx_buf);
		if (rc != 0) {
			const int error = errno;
			if (error != ENOENT && error != ENOTDIR)
				return 0;
			*result = (word_t) -error;
			return 1;
		}
	}

	status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t) &state, 0);
	if (status < 0)
		return 0;

	if (write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_5), &state.statx_buf, sizeof(state.statx_buf)) < 0)
		return 0;

	*result = 0;
	return 1;
#else
	(void) tracee;
	(void) result;
	return 0;
#endif
}
