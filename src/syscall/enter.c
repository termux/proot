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

#include <errno.h>       /* errno(3), E* */
#include <talloc.h>      /* talloc_*, */
#include <sys/un.h>      /* struct sockaddr_un, */
#include <linux/net.h>   /* SYS_*, */
#include <fcntl.h>       /* AT_FDCWD, */
#include <limits.h>      /* PATH_MAX, */
#include <string.h>      /* strcpy */
#include <stdbool.h>     /* bool */
#include <sys/prctl.h>   /* PR_SET_DUMPABLE */
#include <sys/mount.h>   /* MS_BIND, MS_REMOUNT, ... */
#include <sched.h>       /* CLONE_NEW*, */
#include <termios.h>     /* TCSETS, TCSANOW */

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "syscall/heap.h"
#include "extension/extension.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "path/path.h"
#include "path/canon.h"
#include "path/binding.h"
#include "path/temp.h"
#include "arch.h"

/* Older kernel headers may lack these. */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define CLONE_NS_MASK (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | \
		       CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | \
		       CLONE_NEWCGROUP | CLONE_NEWTIME)

/**
 * Translate @path and put the result in the @tracee's memory address
 * space pointed to by the @reg argument of the current syscall. See
 * the documentation of translate_path() about the meaning of
 * @type. This function returns -errno if an error occured, otherwise
 * 0.
 */
static int translate_path2(Tracee *tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type)
{
	char new_path[PATH_MAX];
	int status;

	/* Special case where the argument was NULL. */
	if (path[0] == '\0')
		return 0;

	/* Translate the original path. */
	status = translate_path(tracee, new_path, dir_fd, path, type != SYMLINK);
	if (status < 0)
		return status;

	return set_sysarg_path(tracee, new_path, reg);
}

/**
 * A helper, see the comment of the function above.
 */
static int translate_sysarg(Tracee *tracee, Reg reg, Type type)
{
	char old_path[PATH_MAX];
	int status;

	/* Extract the original path. */
	status = get_sysarg_path(tracee, old_path, reg);
	if (status < 0)
		return status;

	return translate_path2(tracee, AT_FDCWD, old_path, reg, type);
}

/**
 * Canonicalize @user_path as a guest path, relative to the @tracee's
 * cwd when @user_path is relative.  Stores the result in @guest_path
 * with any trailing "/" or "/." stripped, so it can be used as a
 * binding key.  Returns 0 on success, -errno otherwise.
 */
static int guest_canonicalize(Tracee *tracee, const char *user_path,
			      char guest_path[PATH_MAX])
{
	int status;

	if (user_path[0] == '/')
		strcpy(guest_path, "/");
	else {
		status = getcwd2(tracee, guest_path);
		if (status < 0)
			return status;
	}

	status = canonicalize(tracee, user_path, true, guest_path, 0);
	if (status < 0)
		return status;

	chop_finality(guest_path);
	return 0;
}

/**
 * Emulate mount(@src_user, @target_user, @fstype, @flags) by adding a
 * PRoot binding from a host directory to the canonicalized target.
 * Bind mounts use the translated source; "proc"/"sysfs" use the
 * matching host file-system; "tmpfs"/"devpts"/"devtmpfs" get a fresh
 * empty directory.  Any other case is silently ignored: the caller
 * will still see the syscall succeed (we always void it).
 */
static void emulate_mount(Tracee *tracee, const char *src_user,
			  const char *target_user, const char *fstype,
			  unsigned long flags)
{
	char host_path[PATH_MAX];
	char guest_path[PATH_MAX];
	const char *tmpdir;

	if ((flags & MS_REMOUNT) != 0)
		return;

	if ((flags & MS_BIND) != 0) {
		if (translate_path(tracee, host_path, AT_FDCWD, src_user, true) < 0)
			return;
	}
	else if (strcmp(fstype, "proc") == 0)
		strcpy(host_path, "/proc");
	else if (strcmp(fstype, "sysfs") == 0)
		strcpy(host_path, "/sys");
	else if (   strcmp(fstype, "tmpfs") == 0
		 || strcmp(fstype, "devpts") == 0
		 || strcmp(fstype, "devtmpfs") == 0) {
		tmpdir = create_temp_directory(tracee->fs, "proot-tmpfs-");
		if (tmpdir == NULL)
			return;
		strncpy(host_path, tmpdir, PATH_MAX - 1);
		host_path[PATH_MAX - 1] = '\0';
	}
	else
		return;

	chop_finality(host_path);

	if (guest_canonicalize(tracee, target_user, guest_path) < 0)
		return;

	(void) insort_binding3(tracee, tracee->fs, host_path, guest_path);
}

/**
 * Emulate pivot_root(@new_root_user, @put_old_user) by changing the
 * tracee's root binding to point at @new_root_user (translated to
 * host) and re-exposing the previous root at @put_old_user, so that
 * sandbox helpers like bubblewrap can keep accessing the prior
 * file-system through the agreed "oldroot" path.
 */
static void emulate_pivot_root(Tracee *tracee, const char *new_root_user,
			       const char *put_old_user)
{
	char new_root_host[PATH_MAX];
	char new_root_guest[PATH_MAX];
	char put_old_guest[PATH_MAX];
	char old_root_host[PATH_MAX];
	Binding *root_binding;
	size_t prefix_len;
	const char *put_old_after;

	if (translate_path(tracee, new_root_host, AT_FDCWD, new_root_user, true) < 0)
		return;
	chop_finality(new_root_host);

	if (guest_canonicalize(tracee, new_root_user, new_root_guest) < 0)
		return;

	/* put_old is relative to new_root, so resolve it against
	 * new_root_guest rather than the current cwd. */
	if (put_old_user[0] == '/')
		strcpy(put_old_guest, "/");
	else
		strcpy(put_old_guest, new_root_guest);
	if (canonicalize(tracee, put_old_user, true, put_old_guest, 0) < 0)
		return;

	root_binding = get_binding(tracee, GUEST, "/");
	if (root_binding == NULL)
		return;
	strncpy(old_root_host, root_binding->host.path, PATH_MAX - 1);
	old_root_host[PATH_MAX - 1] = '\0';

	remove_binding_from_all_lists(tracee, root_binding);
	(void) insort_binding3(tracee, tracee->fs, new_root_host, "/");

	/* If put_old is a path strictly under new_root, expose the
	 * previous root there.  The pivot_root(".", ".") trick used to
	 * detach the old root leaves new_root and put_old equal; in
	 * that case there is nowhere to expose the old root. */
	prefix_len = strlen(new_root_guest);
	if (   prefix_len > 0
	    && strncmp(put_old_guest, new_root_guest, prefix_len) == 0
	    && (   put_old_guest[prefix_len] == '/'
		|| (prefix_len == 1 && new_root_guest[0] == '/'))) {
		put_old_after = put_old_guest + (prefix_len == 1 ? 0 : prefix_len);
		if (put_old_after[0] == '/' && put_old_after[1] != '\0')
			(void) insort_binding3(tracee, tracee->fs,
					       old_root_host, put_old_after);
	}
}

/**
 * Detect /proc/<pid|self>/{uid_map,gid_map,setgroups}, which sandbox
 * helpers like bubblewrap write to during user-namespace setup.  The
 * tracee cannot really create namespaces under PRoot, so silently
 * redirect those writes to /dev/null.
 */
static bool is_proc_userns_file(const char *path)
{
	const char *p;
	const char *suffix;

	if (strncmp(path, "/proc/", 6) != 0)
		return false;
	p = path + 6;

	if (strncmp(p, "self/", 5) == 0)
		p += 5;
	else {
		const char *digits = p;
		while (*p >= '0' && *p <= '9')
			p++;
		if (p == digits || *p != '/')
			return false;
		p++;
	}

	suffix = p;
	return strcmp(suffix, "uid_map") == 0
	    || strcmp(suffix, "gid_map") == 0
	    || strcmp(suffix, "setgroups") == 0;
}

/**
 * Redirect openat()/open() of /proc/.../uid_map etc. to /dev/null so
 * that writes appear to succeed.  @reg holds the path argument; the
 * path has already been translated to host form.
 */
static void maybe_redirect_userns_file(Tracee *tracee, Reg reg)
{
	char host_path[PATH_MAX];

	if (get_sysarg_path(tracee, host_path, reg) < 0)
		return;
	if (!is_proc_userns_file(host_path))
		return;
	(void) set_sysarg_path(tracee, "/dev/null", reg);
}

/**
 * Translate the input arguments of the current @tracee's syscall in the
 * @tracee->pid process area. This function sets @tracee->status to
 * -errno if an error occured from the tracee's point-of-view (EFAULT
 * for instance), otherwise 0.
 */
int translate_syscall_enter(Tracee *tracee)
{
	int flags;
	int dirfd;
	int olddirfd;
	int newdirfd;

	int status;
	int status2;

	char path[PATH_MAX];
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];

	word_t syscall_number;
	bool special = false;

	status = notify_extensions(tracee, SYSCALL_ENTER_START, 0, 0);
	if (status < 0)
		goto end;
	if (status > 0)
		return 0;

	/* Translate input arguments. */
	syscall_number = get_sysnum(tracee, ORIGINAL);
	switch (syscall_number) {
	default:
		/* Nothing to do. */
		status = 0;
		break;

	case PR_execve:
		status = translate_execve_enter(tracee);
		break;

	case PR_execveat:
		if ((int) peek_reg(tracee, CURRENT, SYSARG_1) == AT_FDCWD) {
			set_sysnum(tracee, PR_execve);
			poke_reg(tracee, SYSARG_1, peek_reg(tracee, CURRENT, SYSARG_2));
			poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_3));
			poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_4));
		} else {
			note(tracee, ERROR, SYSTEM, "execveat() with non-AT_FDCWD fd is not currently supported");
			status = -ENOSYS;
			break;
		}
		status = translate_execve_enter(tracee);
		break;

	case PR_ptrace:
		status = translate_ptrace_enter(tracee);
		break;

	case PR_wait4:
	case PR_waitpid:
		status = translate_wait_enter(tracee);
		break;

	case PR_brk:
		translate_brk_enter(tracee);
		status = 0;
		break;

	case PR_getcwd:
		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_void);
		status = 0;
		break;

	case PR_fchdir:
	case PR_chdir: {
		struct stat statl;
		char *tmp;

		/* The ending "." ensures an error will be reported if
		 * path does not exist or if it is not a directory.  */
		if (syscall_number == PR_chdir) {
			status = get_sysarg_path(tracee, path, SYSARG_1);
			if (status < 0)
				break;

			status = join_paths(2, oldpath, path, ".");
			if (status < 0)
				break;

			dirfd = AT_FDCWD;
		}
		else {
			strcpy(oldpath, ".");
			dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		}

		status = translate_path(tracee, path, dirfd, oldpath, true);
		if (status < 0)
			break;

		status = lstat(path, &statl);
		if (status < 0)
			break;

		/* Check this directory is accessible.  */
		if ((statl.st_mode & S_IXUSR) == 0)
			return -EACCES;

		/* Sadly this method doesn't detranslate statefully,
		 * this means that there's an ambiguity when several
		 * bindings are from the same host path:
		 *
		 *    $ proot -m /tmp:/a -m /tmp:/b fchdir_getcwd /a
		 *    /b
		 *
		 *    $ proot -m /tmp:/b -m /tmp:/a fchdir_getcwd /a
		 *    /a
		 *
		 * A solution would be to follow each file descriptor
		 * just like it is done for cwd.
		 */

		status = detranslate_path(tracee, path, NULL);
		if (status < 0)
			break;

		/* Remove the trailing "/" or "/.".  */
		chop_finality(path);

		tmp = talloc_strdup(tracee->fs, path);
		if (tmp == NULL) {
			status = -ENOMEM;
			break;
		}
		TALLOC_FREE(tracee->fs->cwd);

		tracee->fs->cwd = tmp;
		talloc_set_name_const(tracee->fs->cwd, "$cwd");

		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_void);
		status = 0;
		break;
	}

	case PR_bind:
	case PR_connect: {
		word_t address;
		word_t size;

		address = peek_reg(tracee, CURRENT, SYSARG_2);
		size    = peek_reg(tracee, CURRENT, SYSARG_3);

		status = translate_socketcall_enter(tracee, &address, size);
		if (status <= 0)
			break;

		poke_reg(tracee, SYSARG_2, address);
		poke_reg(tracee, SYSARG_3, sizeof(struct sockaddr_un));

		status = 0;
		break;
	}

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))

#define PEEK_WORD(addr, forced_errno)		\
	peek_word(tracee, addr);		\
	if (errno != 0) {			\
		status = forced_errno ?: -errno; \
		break;				\
	}

#define POKE_WORD(addr, value)			\
	poke_word(tracee, addr, value);		\
	if (errno != 0) {			\
		status = -errno;		\
		break;				\
	}

	case PR_accept:
	case PR_accept4:
		/* Nothing special to do if no sockaddr was specified.  */
		if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0) {
			status = 0;
			break;
		}
		special = true;
		/* Fall through.  */
	case PR_getsockname:
	case PR_getpeername:{
		int size;

		/* Remember: PEEK_WORD puts -errno in status and breaks if an
		 * error occured.  */
		size = (int) PEEK_WORD(peek_reg(tracee, ORIGINAL, SYSARG_3), special ? -EINVAL : 0);

		/* The "size" argument is both used as an input parameter
		 * (max. size) and as an output parameter (actual size).  The
		 * exit stage needs to know the max. size to not overwrite
		 * anything, that's why it is copied in the 6th argument
		 * (unused) before the kernel updates it.  */
		poke_reg(tracee, SYSARG_6, size);

		status = 0;
		break;
	}

	case PR_socketcall: {
		word_t args_addr;
		word_t sock_addr_saved;
		word_t sock_addr;
		word_t size_addr;
		word_t size;

		args_addr = peek_reg(tracee, CURRENT, SYSARG_2);

		switch (peek_reg(tracee, CURRENT, SYSARG_1)) {
		case SYS_BIND:
		case SYS_CONNECT:
			/* Handle these cases below.  */
			status = 1;
			break;

		case SYS_ACCEPT:
		case SYS_ACCEPT4:
			/* Nothing special to do if no sockaddr was specified.  */
			sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
			if (sock_addr == 0) {
				status = 0;
				break;
			}
			special = true;
			/* Fall through.  */
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			/* Remember: PEEK_WORD puts -errno in status and breaks
			 * if an error occured.  */
			size_addr =  PEEK_WORD(SYSARG_ADDR(3), 0);
			size = (int) PEEK_WORD(size_addr, special ? -EINVAL : 0);

			/* See case PR_accept for explanation.  */
			poke_reg(tracee, SYSARG_6, size);
			status = 0;
			break;

		default:
			status = 0;
			break;
		}

		/* An error occured or there's nothing else to do.  */
		if (status <= 0)
			break;

		/* Remember: PEEK_WORD puts -errno in status and breaks if an
		 * error occured.  */
		sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
		size      = PEEK_WORD(SYSARG_ADDR(3), 0);

		sock_addr_saved = sock_addr;
		status = translate_socketcall_enter(tracee, &sock_addr, size);
		if (status <= 0)
			break;

		/* These parameters are used/restored at the exit stage.  */
		poke_reg(tracee, SYSARG_5, sock_addr_saved);
		poke_reg(tracee, SYSARG_6, size);

		/* Remember: POKE_WORD puts -errno in status and breaks if an
		 * error occured.  */
		POKE_WORD(SYSARG_ADDR(2), sock_addr);
		POKE_WORD(SYSARG_ADDR(3), sizeof(struct sockaddr_un));

		status = 0;
		break;
	}

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

	case PR_access:
	case PR_acct:
	case PR_chmod:
	case PR_chown:
	case PR_chown32:
	case PR_chroot:
	case PR_getxattr:
	case PR_listxattr:
	case PR_mknod:
	case PR_oldstat:
	case PR_creat:
	case PR_removexattr:
	case PR_setxattr:
	case PR_stat:
	case PR_stat64:
	case PR_statfs:
	case PR_statfs64:
	case PR_swapoff:
	case PR_swapon:
	case PR_truncate:
	case PR_truncate64:
	case PR_uselib:
	case PR_utime:
	case PR_utimes:
		status = translate_sysarg(tracee, SYSARG_1, REGULAR);
		break;

	/* Pretend namespace/unmount syscalls succeed without doing
	 * anything; PRoot can't really create namespaces, and sandbox
	 * helpers like bubblewrap only check the return value.  */
	case PR_unshare:
	case PR_setns:
	case PR_umount:
	case PR_umount2:
		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_void);
		status = 0;
		break;

	/* Strip CLONE_NEW* flags from clone(2)/clone3(2) so the
	 * syscall doesn't fail with EPERM on kernels that disallow
	 * unprivileged namespace creation (typical on Android).  The
	 * fork/thread itself still proceeds normally and PRoot keeps
	 * tracking the child through PTRACE_EVENT_CLONE.  */
	case PR_clone: {
		word_t flags = peek_reg(tracee, CURRENT, SYSARG_1);
		if ((flags & CLONE_NS_MASK) != 0)
			poke_reg(tracee, SYSARG_1, flags & ~(word_t) CLONE_NS_MASK);
		status = 0;
		break;
	}

	case PR_clone3: {
		word_t args_addr = peek_reg(tracee, CURRENT, SYSARG_1);
		word_t flags;

		if (args_addr != 0) {
			errno = 0;
			flags = peek_word(tracee, args_addr);
			if (errno == 0 && (flags & CLONE_NS_MASK) != 0)
				poke_word(tracee, args_addr,
					  flags & ~(word_t) CLONE_NS_MASK);
		}
		status = 0;
		break;
	}

	/* mount(2) and pivot_root(2) are emulated by translating them
	 * into PRoot bindings (see emulate_mount/emulate_pivot_root)
	 * so the resulting paths actually become accessible.  */
	case PR_mount: {
		char src_user[PATH_MAX];
		char target_user[PATH_MAX];
		char fstype[256];
		word_t fstype_addr;
		unsigned long flags;

		fstype[0] = '\0';

		if (get_sysarg_path(tracee, src_user, SYSARG_1) >= 0
		    && get_sysarg_path(tracee, target_user, SYSARG_2) >= 0) {
			fstype_addr = peek_reg(tracee, CURRENT, SYSARG_3);
			if (fstype_addr != 0)
				(void) read_string(tracee, fstype, fstype_addr,
						   sizeof(fstype) - 1);
			flags = peek_reg(tracee, CURRENT, SYSARG_4);
			emulate_mount(tracee, src_user, target_user, fstype, flags);
		}

		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_void);
		status = 0;
		break;
	}

	case PR_pivot_root: {
		char new_root_user[PATH_MAX];
		char put_old_user[PATH_MAX];

		if (get_sysarg_path(tracee, new_root_user, SYSARG_1) >= 0
		    && get_sysarg_path(tracee, put_old_user, SYSARG_2) >= 0)
			emulate_pivot_root(tracee, new_root_user, put_old_user);

		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_void);
		status = 0;
		break;
	}

	case PR_open:
		flags = peek_reg(tracee, CURRENT, SYSARG_2);

		if (tracee->execfn_addr != 0
		    && read_string(tracee, path, peek_reg(tracee, CURRENT, SYSARG_1), PATH_MAX) > 0
		    && strcmp(path, "/proc/self/auxv") == 0) {
			tracee->sysexit_pending = true;
			tracee->restart_how = PTRACE_SYSCALL;
		}

		if (   ((flags & O_NOFOLLOW) != 0)
		    || ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
			status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
		else
			status = translate_sysarg(tracee, SYSARG_1, REGULAR);
		if (status >= 0)
			maybe_redirect_userns_file(tracee, SYSARG_1);
		break;

	case PR_fchownat:
	case PR_fstatat64:
	case PR_newfstatat:
	case PR_utimensat:
	case PR_name_to_handle_at:
		dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

		status = get_sysarg_path(tracee, path, SYSARG_2);
		if (status < 0)
			break;

		flags = (  syscall_number == PR_fchownat
			|| syscall_number == PR_name_to_handle_at)
			? peek_reg(tracee, CURRENT, SYSARG_5)
			: peek_reg(tracee, CURRENT, SYSARG_4);

		if ((flags & AT_SYMLINK_NOFOLLOW) != 0)
			status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
		else
			status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
		break;

	case PR_fchmodat:
	case PR_faccessat:
	case PR_faccessat2:
	case PR_futimesat:
	case PR_mknodat:
		dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

		status = get_sysarg_path(tracee, path, SYSARG_2);
		if (status < 0)
			break;

		status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
		break;

	case PR_inotify_add_watch:
		flags = peek_reg(tracee, CURRENT, SYSARG_3);

		if ((flags & IN_DONT_FOLLOW) != 0)
			status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
		else
			status = translate_sysarg(tracee, SYSARG_2, REGULAR);
		break;

	case PR_readlink:
	case PR_lchown:
	case PR_lchown32:
	case PR_lgetxattr:
	case PR_llistxattr:
	case PR_lremovexattr:
	case PR_lsetxattr:
	case PR_lstat:
	case PR_lstat64:
	case PR_oldlstat:
	case PR_unlink:
	case PR_rmdir:
	case PR_mkdir:
		status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
		break;

	case PR_linkat:
		olddirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		newdirfd = peek_reg(tracee, CURRENT, SYSARG_3);
		flags    = peek_reg(tracee, CURRENT, SYSARG_5);

		status = get_sysarg_path(tracee, oldpath, SYSARG_2);
		if (status < 0)
			break;

		status = get_sysarg_path(tracee, newpath, SYSARG_4);
		if (status < 0)
			break;

		if ((flags & AT_SYMLINK_FOLLOW) != 0)
			status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, REGULAR);
		else
			status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, SYMLINK);
		if (status < 0)
			break;

		status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
		break;

	case PR_openat2: {
		/* int openat2(int dirfd, const char *pathname,
		 *             struct open_how *how, size_t size);
		 *
		 * Rewrite into openat() and translate it as such: the path is
		 * in SYSARG_2 like openat(), but the open flags live inside the
		 * open_how struct rather than in a register, so move them into
		 * SYSARG_3.  The how.resolve flags (RESOLVE_BENEATH, ...) are
		 * dropped: they reject the absolute host paths PRoot produces,
		 * and PRoot already keeps path resolution inside the rootfs.  */
		struct proot_open_how how = {};
		word_t how_size = peek_reg(tracee, CURRENT, SYSARG_4);
		if (how_size > sizeof(how))
			how_size = sizeof(how);
		status = read_data(tracee, &how, peek_reg(tracee, CURRENT, SYSARG_3), how_size);
		if (status < 0)
			break;
		set_sysnum(tracee, PR_openat);
		poke_reg(tracee, SYSARG_3, how.flags);
		poke_reg(tracee, SYSARG_4, how.mode);
	}
		/* Fall through.  */

	case PR_openat:
		dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		flags = peek_reg(tracee, CURRENT, SYSARG_3);

		status = get_sysarg_path(tracee, path, SYSARG_2);
		if (status < 0)
			break;

		if (tracee->execfn_addr != 0 && strcmp(path, "/proc/self/auxv") == 0) {
			tracee->sysexit_pending = true;
			tracee->restart_how = PTRACE_SYSCALL;
		}

		if (   ((flags & O_NOFOLLOW) != 0)
			|| ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
			status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
		else
			status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
		if (status >= 0)
			maybe_redirect_userns_file(tracee, SYSARG_2);
		break;

	case PR_readlinkat:
	case PR_unlinkat:
	case PR_mkdirat:
		dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

		status = get_sysarg_path(tracee, path, SYSARG_2);
		if (status < 0)
			break;

		status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
		break;

	case PR_link:
	case PR_rename:
		status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
		if (status < 0)
			break;

		status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
		break;

	case PR_renameat:
	case PR_renameat2:
		olddirfd = peek_reg(tracee, CURRENT, SYSARG_1);
		newdirfd = peek_reg(tracee, CURRENT, SYSARG_3);

		status = get_sysarg_path(tracee, oldpath, SYSARG_2);
		if (status < 0)
			break;

		status = get_sysarg_path(tracee, newpath, SYSARG_4);
		if (status < 0)
			break;

		status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, SYMLINK);
		if (status < 0)
			break;

		status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
		break;

	case PR_symlink:
		status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
		break;

	case PR_symlinkat:
		newdirfd = peek_reg(tracee, CURRENT, SYSARG_2);

		status = get_sysarg_path(tracee, newpath, SYSARG_3);
		if (status < 0)
			break;

		status = translate_path2(tracee, newdirfd, newpath, SYSARG_3, SYMLINK);
		break;

	case PR_statx:
		newdirfd = peek_reg(tracee, CURRENT, SYSARG_1);

		status = get_sysarg_path(tracee, newpath, SYSARG_2);
		if (status < 0)
			break;

		status = translate_path2(
			tracee,
			newdirfd,
			newpath,
			SYSARG_2,
			(peek_reg(tracee, CURRENT, SYSARG_3) & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR
		);
		break;

	case PR_prctl:
		/* Prevent tracees from setting dumpable flag.
		 * (Otherwise it could break tracee memory access)  */
		if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_SET_DUMPABLE) {
			poke_reg(tracee, SYSARG_RESULT, 0);
			set_sysnum(tracee, PR_void);
			status = 0;
		}
		/* On kernels that don't support PTRACE_O_TRACESECCOMP,
		 * SECCOMP_RET_TRACE causes filtered syscalls to return
		 * -ENOSYS to the tracee without generating a ptrace event.
		 * If a tracee installs its own SECCOMP_MODE_FILTER, the
		 * syscalls proot must intercept (open, execve, ...) would
		 * silently fail from proot's perspective.  Block the filter
		 * installation so proot's PTRACE_SYSCALL path keeps working.
		 * This situation is typical on old ARM 32-bit Android kernels
		 * that backported seccomp but not PTRACE_O_TRACESECCOMP.  */
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
		if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_SET_SECCOMP
		    && peek_reg(tracee, CURRENT, SYSARG_2) == SECCOMP_MODE_FILTER
		    && !seccomp_ptrace_event_is_supported()) {
			VERBOSE(tracee, 1, "blocking tracee prctl(PR_SET_SECCOMP, "
				"SECCOMP_MODE_FILTER): kernel lacks "
				"PTRACE_EVENT_SECCOMP support");
			poke_reg(tracee, SYSARG_RESULT, (word_t) -EPERM);
			set_sysnum(tracee, PR_void);
			status = 0;
		}
		/* Need sysexit to patch AT_EXECFN in the returned buffer. */
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
		if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_GET_AUXV) {
			tracee->sysexit_pending = true;
			tracee->restart_how = PTRACE_SYSCALL;
		}
		break;

#ifdef __ANDROID__
	case PR_ioctl:
		/* Using literal value because Termux build system patches TCSAFLUSH */
		if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETS + 2 /* + TCSAFLUSH */) {
			poke_reg(tracee, SYSARG_2, TCSETS + TCSANOW);
		}

		if (peek_reg(tracee, CURRENT, SYSARG_2) == TCGETS2) {
			poke_reg(tracee, SYSARG_2, TCGETS);
		}

		if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETS2) {
			poke_reg(tracee, SYSARG_2, TCSETS);
		}

		if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETSW2) {
			poke_reg(tracee, SYSARG_2, TCSETSW);
		}

		if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETSF2) {
			poke_reg(tracee, SYSARG_2, TCSETS);
		}

		break;
#endif
	
	case PR_memfd_create:
		{
			char memfd_name[20] = {};
			if (read_string(tracee, memfd_name, peek_reg(tracee, CURRENT, SYSARG_1), sizeof(memfd_name) - 1) < 0) {
				/* Failed to read memfd name, do nothing and let normal memfd proceed.  */
				break;
			}
			/* If this memfd is one of those used by Qt/QML for executable code,
			 * deny memfd_create() call and let Qt fall back to anonymous mmap.  */
			if (0 == strncmp(memfd_name, "JITCode:", 8)) {
				status = -EACCES;
			}
			/* php8.3 attempts using memfd as lock through fcntl(F_SETLKW),
			 * which is not allowed on Android,
			 * deny memfd_create() call and let php fall back to open(O_TMPFILE).
			 * https://github.com/php/php-src/blob/26c432d850c153aaf79a1b24e4753bc0533e02b0/ext/opcache/zend_shared_alloc.c#L91
			 */
			if (0 == strcmp(memfd_name, "opcache_lock")) {
				status = -EACCES;
			}
			/* apk-tools v3 use memfd_create + execveat, which is not supported under PRoot
			 * https://github.com/termux/proot-distro/issues/595#issuecomment-3705344471
			 * https://git.alpinelinux.org/apk-tools/tree/src/package.c?h=v3.0.3#n737
			 */
			if (0 == strncmp(memfd_name, "lib/apk/exec/", 13)) {
				status = -EACCES;
			}
			break;
		}
	case PR_close:
		/* Stop tracking auxv_fd once the tracee closes it. */
		if (tracee->auxv_fd >= 0
		    && (int) peek_reg(tracee, CURRENT, SYSARG_1) == tracee->auxv_fd)
			tracee->auxv_fd = -1;
		break;

	}


end:
	status2 = notify_extensions(tracee, SYSCALL_ENTER_END, status, 0);
	if (status2 < 0)
		status = status2;

	return status;
}

