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

#include <string.h>    /* string(3), */
#include <stdlib.h>    /* free(3), */
#include <stdarg.h>    /* va_*(3), */
#include <assert.h>    /* assert(3), */
#include <fcntl.h>     /* AT_*,  */
#include <unistd.h>    /* readlink*(2), *stat(2), getpid(2), */
#include <sys/types.h> /* pid_t, */
#include <sys/stat.h>  /* S_ISDIR, */
#include <dirent.h>    /* opendir(3), readdir(3), */
#include <stdio.h>     /* snprintf(3), */
#include <errno.h>     /* E*, */
#include <stddef.h>    /* ptrdiff_t, */
#include <inttypes.h>  /* PRI*, */

#include "path/path.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/proc.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"

#include "compat.h"

/**
 * Copy in @result the concatenation of several paths (@number_paths)
 * and adds a path separator ('/') in between when needed. This
 * function returns -errno if an error occured, otherwise it returns 0.
 */
int join_paths(int number_paths, char result[PATH_MAX], ...)
{
	va_list paths;
	size_t length;
	int status;
	int i;

	result[0] = '\0';
	length = 0;
	status = 0;

	/* Parse the list of variadic arguments. */
	va_start(paths, result);
	for (i = 0; i < number_paths; i++) {
		const char *path;
		size_t path_length;
		size_t new_length;

		path = va_arg(paths, const char *);
		if (path == NULL)
			continue;
		path_length = strlen(path);

		/* A new path separator is needed.  */
		if (length > 0 && result[length - 1] != '/' && path[0] != '/') {
			new_length = length + path_length + 1;
			if (new_length + 1 >= PATH_MAX) {
				status = -ENAMETOOLONG;
				break;
			}
			strcat(result + length, "/");
			strcat(result + length, path);
			length = new_length;
		}
		/* There are already two path separators.  */
		else if (length > 0 && result[length - 1] == '/' && path[0] == '/') {
			new_length = length + path_length - 1;
			if (new_length + 1 >= PATH_MAX) {
				status = -ENAMETOOLONG;
				break;
			}
			strcat(result + length, path + 1);
			length += path_length - 1;
		}
		/* There's already one path separator or result[] is empty.  */
		else {
			new_length = length + path_length;
			if (new_length + 1 >= PATH_MAX) {
				status = -ENAMETOOLONG;
				break;
			}
			strcat(result + length, path);
			length += path_length;
		}

		status = 0;
	}
	va_end(paths);

	return status;
}

/**
 * Put in @guest_path the canonicalized form of @path, like realpath2()
 * but without the translation: the guest path can't be told from the
 * host one when that latter is bound elsewhere too, for instance
 * "-b /bin:/foo" makes "/usr/bin/test" "/foo/test" as well, and a
 * relative symlink doesn't lead to the same place from both.  This
 * function returns -errno on error, otherwise 0.
 */
static int guest_realpath(Tracee *tracee, char guest_path[PATH_MAX], const char *path, bool deref_final)
{
	char base[PATH_MAX];
	char joined[PATH_MAX];
	int status;

	if (tracee == NULL)
		return realpath2(tracee, guest_path, path, deref_final);

	if (path[0] == '/')
		strcpy(base, "/");
	else {
		status = getcwd2(tracee, base);
		if (status < 0)
			return status;
	}

	status = join_paths(2, joined, base, path);
	if (status < 0)
		return status;

	strcpy(guest_path, "/");
	return canonicalize(tracee, joined, deref_final, guest_path, 0);
}

/**
 * Put in @guest_path the full path to the given shell @command.  The
 * @command is searched in @paths if not null, otherwise in $PATH
 * (relatively to the @tracee's file-system name-space).  This
 * function always returns -1 on error, otherwise 0.
 */
int which(Tracee *tracee, const char *paths, char guest_path[PATH_MAX], const char *command)
{
	char host_path[PATH_MAX];
	char path[PATH_MAX];
	const char *cursor;
	struct stat statr;
	int status;

	bool is_explicit;
	bool found;

	assert(command != NULL);
	is_explicit = (strchr(command, '/') != NULL);

	/* Is the command available without any $PATH look-up?  */
	status = realpath2(tracee, host_path, command, true);
	if (status == 0 && stat(host_path, &statr) == 0) {
		if (is_explicit && !S_ISREG(statr.st_mode)) {
			note(tracee, ERROR, USER, "'%s' is not a regular file", command);
			return -EACCES;
		}

		if (is_explicit && (statr.st_mode & S_IXUSR) == 0) {
			note(tracee, ERROR, USER, "'%s' is not executable", command);
			return -EACCES;
		}

		/* Don't dereference the final component to preserve
		 * argv0 in case it is a symlink to script.  */
		found = (guest_realpath(tracee, guest_path, command, false) == 0);
	}
	else
		found = false;

	/* Is the the explicit command was found?  */
	if (is_explicit) {
		if (found)
			return 0;
		else
			goto not_found;
	}

	/* Otherwise search the command in $PATH.  */
	paths = paths ?: getenv("PATH");
	if (paths == NULL || strcmp(paths, "") == 0)
		goto not_found;

	cursor = paths;
	do {
		size_t length;

		length = strcspn(cursor, ":");
		cursor += length + 1;

		if (length >= PATH_MAX)
			continue;
		else if (length == 0)
			strcpy(path, ".");
		else {
			strncpy(path, cursor - length - 1, length);
			path[length] = '\0';
		}

		/* Avoid buffer-overflow.  */
		if (length + strlen(command) + 2 >= PATH_MAX)
			continue;

		strcat(path, "/");
		strcat(path, command);

		status = realpath2(tracee, host_path, path, true);
		if (status == 0
		    && stat(host_path, &statr) == 0
		    && S_ISREG(statr.st_mode)
		    && (statr.st_mode & S_IXUSR) != 0
		    /* Don't dereference the final component to preserve
		     * argv0 in case it is a symlink to script.  */
		    && guest_realpath(tracee, guest_path, path, false) == 0)
			return 0;
	} while (*(cursor - 1) != '\0');

not_found:
	status = getcwd2(tracee, path);
	if (status < 0)
		strcpy(path, "<unknown>");

	note(tracee, ERROR, USER, "'%s' not found (root = %s, cwd = %s, $PATH=%s)",
		command, get_root(tracee), path, paths);

	/* Check if the command was found without any $PATH look-up
	 * but it didn't contain "/".  */
	if (found && !is_explicit)
		note(tracee, ERROR, USER,
			"to execute a local program, use the './' prefix, for example: ./%s", command);

	return -1;
}

/**
 * Put in @host_path the canonicalized form of @path.  In the nominal
 * case (@tracee == NULL), this function is barely equivalent to
 * realpath(), but when doing sub-reconfiguration, the path is
 * canonicalized relatively to the current @tracee's file-system
 * name-space.  This function returns -errno on error, otherwise 0.
 */
int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path, bool deref_final)
{
	char parent[PATH_MAX];
	const char *name;
	int status;

	if (tracee != NULL)
		return translate_path(tracee, host_path, AT_FDCWD, path, deref_final);

	name = strrchr(path, '/');
	name = (name == NULL ? path : name + 1);

	/* realpath(3) dereferences the final component in any case: a
	 * symbolic link to a multi-call program, "false" to coreutils
	 * on Termux for instance, would be run under the name of that
	 * program.  */
	if (deref_final || name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return (realpath(path, host_path) == NULL ? -errno : 0);

	if ((size_t) (name - path) >= PATH_MAX)
		return -ENAMETOOLONG;
	memcpy(parent, path, name - path);
	parent[name - path] = '\0';

	if (realpath(parent[0] != '\0' ? parent : ".", host_path) == NULL)
		return -errno;
	strcpy(parent, host_path);

	status = join_paths(2, host_path, parent, name);
	return status;
}

/**
 * Put in @guest_path the canonicalized current working directory.  In
 * the nominal case (@tracee == NULL), this function is barely
 * equivalent to realpath(), but when doing sub-reconfiguration, the
 * path is canonicalized relatively to the current @tracee's
 * file-system name-space.  This function returns -errno on error,
 * otherwise 0.
 */
int getcwd2(Tracee *tracee, char guest_path[PATH_MAX])
{
	if (tracee == NULL) {
		if (getcwd(guest_path, PATH_MAX) == NULL)
			return -errno;
	}
	else {
		if (strlen(tracee->fs->cwd) >= PATH_MAX)
			return -ENAMETOOLONG;

		strcpy(guest_path, tracee->fs->cwd);
	}

	return 0;
}

/**
 * Remove the trailing "/" or "/.".
 */
void chop_finality(char *path)
{
	size_t length = strlen(path);

	if (path[length - 1] == '.') {
		assert(length >= 2);
		/* Special case for "/." */
		if (length == 2)
			path[length - 1] = '\0';
		else
			path[length - 2] = '\0';
	}
	else if (path[length - 1] == '/') {
		/* Special case for "/" */
		if (length > 1)
			path[length - 1] = '\0';
	}
}

/**
 * Canonicalize @user_path as a guest path, relative to the @tracee's
 * cwd when @user_path is relative.  Stores the result in @guest_path
 * with any trailing "/" or "/." stripped, so it can be used as a
 * binding key.  Returns 0 on success, -errno otherwise.
 */
int guest_canonicalize(Tracee *tracee, const char *user_path,
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
 * Put in @path the result of readlink(/proc/@pid/fd/@fd).  This
 * function returns -errno if an error occured, othrwise 0.
 */
int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX])
{
	char link[32]; /* 32 > sizeof("/proc//cwd") + sizeof(#ULONG_MAX) */
	int status;

	/* Format the path to the "virtual" link. */
	status = snprintf(link, sizeof(link), "/proc/%d/fd/%d",	pid, fd);
	if (status < 0)
		return -EBADF;
	if ((size_t) status >= sizeof(link))
		return -EBADF;

	/* Read the value of this "virtual" link. */
	status = readlink(link, path, PATH_MAX);
	if (status < 0)
		return -EBADF;
	if (status >= PATH_MAX)
		return -ENAMETOOLONG;
	path[status] = '\0';

	return 0;
}

/**
 * Guest paths descriptors were opened through.  The kernel reports the
 * file a descriptor refers to by its host path only, and several guest
 * paths lead there when bindings overlap: once a sandbox helper did
 * pivot_root(2), then bind mounted "/" in the new root, "/oldroot" and
 * "/newroot" lead to the same host directory.  Detranslation picks one
 * of them (see detranslate_path()).  That doesn't matter for the file
 * itself, but it does for a directory used as the base of a relative
 * path (openat(2)) or as the target of a mount(2) through
 * "/proc/self/fd/<FD>", as bubblewrap does: what is below "/oldroot/dev"
 * isn't what is below "/newroot/dev".
 *
 * Only the descriptors opened with O_PATH, or by openat2(2), are
 * remembered, since this requires the exit stage of the syscall (see
 * translate_syscall_exit()).  An entry is forgotten when its
 * descriptor is closed, or when its process calls execve(2), but
 * there's no bookkeeping for dup(2) or fork(2): it is only used for
 * the very descriptor of the very process that opened it, as long as
 * it refers to the same host path and its guest path still leads
 * there.
 */
#define FD_PATHS_SIZE 64

static struct {
	pid_t pid;
	int fd;
	char *guest;      /* The path the tracee opened, canonicalized.  */
	char *translated; /* Where the bindings lead this latter.  */
	char *host;       /* The host path the kernel reports.  */
} fd_paths[FD_PATHS_SIZE];
static size_t fd_paths_next;

/**
 * Remember that the descriptor @fd of the process @pid was opened
 * through @guest_path, a canonicalized guest path, with the bindings
 * of @tracee.
 */
void remember_fd_path(const Tracee *tracee, pid_t pid, int fd, const char *guest_path)
{
	char translated_path[PATH_MAX];
	char real_path[PATH_MAX];
	char *guest = NULL;
	char *translated = NULL;
	char *host = NULL;
	size_t index;
	size_t slot;

	/* Reuse the entry of this very descriptor, if any: it's stale.  */
	slot = FD_PATHS_SIZE;
	for (index = 0; index < FD_PATHS_SIZE; index++) {
		if (   fd_paths[index].guest != NULL
		    && fd_paths[index].pid == pid
		    && fd_paths[index].fd == fd) {
			slot = index;
			break;
		}
	}

	if (slot == FD_PATHS_SIZE) {
		slot = fd_paths_next;
		fd_paths_next = (fd_paths_next + 1) % FD_PATHS_SIZE;
	}

	/* Note: entries live as long as PRoot does, they are not
	 * talloc'ed from any tracee -- descriptors outlive the process
	 * that opened them.  */
	strcpy(translated_path, guest_path);
	if (   substitute_binding(tracee, GUEST, translated_path) >= 0
	    && readlink_proc_pid_fd(pid, fd, real_path) == 0
	    && real_path[0] == '/') {
		guest      = strdup(guest_path);
		translated = strdup(translated_path);
		host       = strdup(real_path);
	}

	free(fd_paths[slot].guest);
	free(fd_paths[slot].translated);
	free(fd_paths[slot].host);

	if (guest == NULL || translated == NULL || host == NULL) {
		free(guest);
		free(translated);
		free(host);
		guest = translated = host = NULL;
	}

	fd_paths[slot].pid        = pid;
	fd_paths[slot].fd         = fd;
	fd_paths[slot].guest      = guest;
	fd_paths[slot].translated = translated;
	fd_paths[slot].host       = host;
}

/**
 * Forget the guest path the descriptor @fd of the process @pid was
 * opened through, as it's closed, or the ones of all its descriptors
 * if @fd is negative.
 */
void forget_fd_path(pid_t pid, int fd)
{
	size_t index;

	for (index = 0; index < FD_PATHS_SIZE; index++) {
		if (   fd_paths[index].guest == NULL
		    || fd_paths[index].pid != pid
		    || (fd >= 0 && fd_paths[index].fd != fd))
			continue;

		free(fd_paths[index].guest);
		free(fd_paths[index].translated);
		free(fd_paths[index].host);
		fd_paths[index].guest = fd_paths[index].translated = fd_paths[index].host = NULL;
	}
}

/**
 * Replace @path, the host path the descriptor @fd of the process @pid
 * refers to, with the guest path this descriptor was opened through,
 * if it is known and still leads there with the bindings of @tracee
 * (see remember_fd_path()).  This function returns whether @path was
 * replaced.
 */
static bool recall_fd_path(const Tracee *tracee, pid_t pid, int fd, char path[PATH_MAX])
{
	char translated[PATH_MAX];
	size_t index;

	for (index = 0; index < FD_PATHS_SIZE; index++) {
		if (   fd_paths[index].guest == NULL
		    || fd_paths[index].pid != pid
		    || fd_paths[index].fd != fd)
			continue;

		if (strcmp(fd_paths[index].host, path) != 0)
			return false;

		strcpy(translated, fd_paths[index].guest);
		if (   substitute_binding(tracee, GUEST, translated) < 0
		    || strcmp(translated, fd_paths[index].translated) != 0)
			return false;

		strcpy(path, fd_paths[index].guest);
		return true;
	}

	return false;
}

/**
 * Copy in @guest_path the guest path of the file the descriptor @fd
 * of @tracee refers to.  This function returns -errno if an error
 * occured, otherwise 0.
 */
int get_fd_guest_path(Tracee *tracee, int fd, char guest_path[PATH_MAX])
{
	int status;

	/* /proc/@tracee->pid/fd/@fd -> guest_path.  */
	status = readlink_proc_pid_fd(tracee->pid, fd, guest_path);
	if (status < 0)
		return status;

	/* Named file descriptors may reference special objects like
	 * pipes, sockets, inodes, ...  Such objects do not belong to
	 * the file-system.  */
	if (guest_path[0] != '/')
		return -ENOTDIR;

	if (recall_fd_path(tracee, tracee->pid, fd, guest_path))
		return 0;

	/* Remove the leading "root" part of the base (required!). */
	status = detranslate_path(tracee, guest_path, NULL);
	if (status < 0)
		return status;

	return 0;
}

/**
 * Copy in @result the equivalent of "@tracee->root + canon(@dir_fd +
 * @user_path)".  If @user_path is not absolute then it is relative to
 * the directory referred by the descriptor @dir_fd (AT_FDCWD is for
 * the current working directory).  See the documentation of
 * canonicalize() for the meaning of @deref_final.  This function
 * returns -errno if an error occured, otherwise 0.
 */
int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
		const char *user_path, bool deref_final)
{
	return translate_path_guest(tracee, result, NULL, dir_fd, user_path, deref_final);
}

/**
 * Same as translate_path(), but also copy in @guest_path, unless it is
 * NULL, the canonicalized guest path that was translated into @result
 * (without final "/" nor "/."), or an empty string if an extension
 * translated @user_path by itself.
 */
int translate_path_guest(Tracee *tracee, char result[PATH_MAX], char guest_path[PATH_MAX],
			int dir_fd, const char *user_path, bool deref_final)
{
	char joined_path[PATH_MAX];
	int status;

	if (guest_path != NULL)
		guest_path[0] = '\0';

	/* Use "/" as the base if it is an absolute guest path. */
	if (user_path[0] == '/') {
		strcpy(result, "/");
	}
	/* It is relative to a directory referred by a descriptor, see
	 * openat(2) for details. */
	else if (dir_fd != AT_FDCWD) {
		status = get_fd_guest_path(tracee, dir_fd, result);
		if (status < 0)
			return status;
	}
	/* It is relative to the current working directory.  */
	else {
		status = getcwd2(tracee, result);
		if (status < 0)
			return status;
	}

	VERBOSE(tracee, 2, "vpid %" PRIu64 ": translate(\"%s\" + \"%s\")",
		tracee != NULL ? tracee->vpid : 0, result, user_path);

	status = notify_extensions(tracee, GUEST_PATH, (intptr_t) result, (intptr_t) user_path);
	if (status < 0)
		return status;
	if (status > 0)
		goto skip;

	/* So far "result" was used as a base path, it's time to join
	 * it to the user path.  */
	assert(result[0] == '/');
	status = join_paths(2, joined_path, result, user_path);
	if (status < 0)
		return status;
	strcpy(result, "/");

	/* Canonicalize regarding the new root. */
	status = canonicalize(tracee, joined_path, deref_final, result, 0);
	if (status < 0)
		return status;

	/* Without the final "/" or "/." canonicalize() keeps to tell a
	 * directory is expected.  */
	if (guest_path != NULL) {
		size_t length;

		strcpy(guest_path, result);
		length = strlen(guest_path);
		if (length >= 2 && strcmp(guest_path + length - 2, "/.") == 0)
			guest_path[length > 2 ? length - 2 : 1] = '\0';
		else if (length > 1 && guest_path[length - 1] == '/')
			guest_path[length - 1] = '\0';
	}

	/* Final binding substitution to convert "result" into a host
	 * path, since canonicalize() works from the guest
	 * point-of-view.  */
	status = substitute_binding(tracee, GUEST, result);
	if (status < 0)
		return status;

skip:
	VERBOSE(tracee, 2, "vpid %" PRIu64 ":          -> \"%s\"",
		tracee != NULL ? tracee->vpid : 0, result);

	status = notify_extensions(tracee, TRANSLATED_PATH, (intptr_t) result, 0);
	if (status < 0)
		return status;

	return 0;
}

/**
 * Remove/substitute the leading part of a "translated" @path.  It
 * returns 0 if no transformation is required (ie. symmetric binding),
 * otherwise it returns the size in bytes of the updated @path,
 * including the end-of-string terminator.  On error it returns
 * -errno.
 */
int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char t_referrer[PATH_MAX])
{
	size_t prefix_length;
	ssize_t new_length;

	bool sanity_check;
	bool follow_binding;

	/* Sanity check.  */
	if (strnlen(path, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;

	/* Don't try to detranslate relative paths (typically the
	 * target of a relative symbolic link). */
	if (path[0] != '/')
		return 0;

	/* Is it a symlink?  */
	if (t_referrer != NULL) {
		Comparison comparison;

		sanity_check = false;
		follow_binding = false;

		/* In some cases bindings have to be resolved.  */
		comparison = compare_paths("/proc", t_referrer);
		if (comparison == PATH1_IS_PREFIX) {
			/* Some links in "/proc" are generated
			 * dynamically by the kernel.  PRoot has to
			 * emulate some of them.  */
			char proc_path[PATH_MAX];
			int fd_pid;
			int fd_number;
			char extra;

			/* A descriptor may have been opened through
			 * another guest path than the one picked below,
			 * see remember_fd_path().  */
			if (   sscanf(t_referrer, "/proc/%d/fd/%d%c", &fd_pid, &fd_number, &extra) == 2
			    && recall_fd_path(tracee, fd_pid, fd_number, path))
				return strlen(path) + 1;

			strcpy(proc_path, path);
			new_length = readlink_proc2(tracee, proc_path, t_referrer);
			if (new_length < 0)
				return new_length;
			if (new_length != 0) {
				strcpy(path, proc_path);
				return new_length + 1;
			}

			/* Always resolve bindings for symlinks in
			 * "/proc", they always point to the emulated
			 * file-system namespace by design. */
			follow_binding = true;
		}
		else if (!belongs_to_guestfs(tracee, t_referrer)) {
			const char *binding_referree;
			const char *binding_referrer;

			binding_referree = get_path_binding(tracee, HOST, path);
			binding_referrer = get_path_binding(tracee, HOST, t_referrer);
			assert(binding_referrer != NULL);

			/* Resolve bindings for symlinks that belong
			 * to a binding and point to the same binding.
			 * For example, if "-b /lib:/foo" is specified
			 * and the symlink "/lib/a -> /lib/b" exists
			 * in the host rootfs namespace, then it
			 * should appear as "/foo/a -> /foo/b" in the
			 * guest rootfs namespace for consistency
			 * reasons.  */
			if (binding_referree != NULL) {
				comparison = compare_paths(binding_referree, binding_referrer);
				follow_binding = (comparison == PATHS_ARE_EQUAL);
			}
		}
	}
	else {
		sanity_check = true;
		follow_binding = true;
	}

	if (follow_binding) {
		switch (substitute_binding(tracee, HOST, path)) {
		case 0:
			return 0;
		case 1:
			return strlen(path) + 1;
		default:
			break;
		}
	}

	switch (compare_paths(get_root(tracee), path)) {
	case PATH1_IS_PREFIX:
		/* Remove the leading part, that is, the "root".  */
		prefix_length = strlen(get_root(tracee));

		/* Special case when path to the guest rootfs == "/". */
		if (prefix_length == 1)
			prefix_length = 0;

		new_length = strlen(path) - prefix_length;
		memmove(path, path + prefix_length, new_length);

		path[new_length] = '\0';
		break;

	case PATHS_ARE_EQUAL:
		/* Special case when path == root. */
		new_length = 1;
		strcpy(path, "/");
		break;

	default:
		/* Ensure the path is within the new root.  */
		if (sanity_check)
			return -EPERM;
		else
			return 0;
	}

	return new_length + 1;
}

/**
 * Check if the translated @host_path belongs to the guest rootfs,
 * that is, isn't from a binding.
 */
bool belongs_to_guestfs(const Tracee *tracee, const char *host_path)
{
	Comparison comparison;

	comparison = compare_paths(get_root(tracee), host_path);
	return (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX);
}

/**
 * Compare @path1 with @path2, which are respectively @length1 and
 * @length2 long.
 *
 * This function works only with paths canonicalized in the same
 * namespace (host/guest)!
 */
Comparison compare_paths2(const char *path1, size_t length1, const char *path2, size_t length2)
{
	size_t length_min;
	bool is_prefix;
	char sentinel;

#if defined DEBUG_OPATH
	assert(length(path1) == length1);
	assert(length(path2) == length2);
#endif
	assert(length1 > 0);
	assert(length2 > 0);

	if (!length1 || !length2) {
		return PATHS_ARE_NOT_COMPARABLE;
	}

	/* Remove potential trailing '/' for the comparison.  */
	if (path1[length1 - 1] == '/')
		length1--;

	if (path2[length2 - 1] == '/')
		length2--;

	if (length1 < length2) {
		length_min = length1;
		sentinel = path2[length_min];
	}
	else {
		length_min = length2;
		sentinel = path1[length_min];
	}

	/* Optimize obvious cases.  */
	if (sentinel != '/' && sentinel != '\0')
		return PATHS_ARE_NOT_COMPARABLE;

	is_prefix = (strncmp(path1, path2, length_min) == 0);

	if (!is_prefix)
		return PATHS_ARE_NOT_COMPARABLE;

	if (length1 == length2)
		return PATHS_ARE_EQUAL;
	else if (length1 < length2)
		return PATH1_IS_PREFIX;
	else if (length1 > length2)
		return PATH2_IS_PREFIX;

	assert(0);
	return PATHS_ARE_NOT_COMPARABLE;
}

Comparison compare_paths(const char *path1, const char *path2)
{
	return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

typedef int (*foreach_fd_t)(const Tracee *tracee, int fd, char path[PATH_MAX]);

/**
 * Call @callback on each open file descriptors of @pid. It returns
 * the status of the first failure, that is, if @callback returned
 * seomthing lesser than 0, otherwise 0.
 */
static int foreach_fd(const Tracee *tracee, foreach_fd_t callback)
{
	struct dirent *dirent;
	char path[PATH_MAX];
	char proc_fd[32]; /* 32 > sizeof("/proc//fd") + sizeof(#ULONG_MAX) */
	int status;
	DIR *dirp;

	/* Format the path to the "virtual" directory. */
	status = snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd", tracee->pid);
	if (status < 0 || (size_t) status >= sizeof(proc_fd))
		return 0;

	/* Open the virtual directory "/proc/$pid/fd". */
	dirp = opendir(proc_fd);
	if (dirp == NULL)
		return 0;

	while ((dirent = readdir(dirp)) != NULL) {
		/* Read the value of this "virtual" link.  Don't use
		 * readlinkat(2) here since it would require Linux >=
		 * 2.6.16 and Glibc >= 2.4, whereas PRoot is supposed
		 * to work on any Linux 2.6 systems.  */

		char tmp[PATH_MAX];
		if (strlen(proc_fd) + strlen(dirent->d_name) + 1 >= PATH_MAX)
			continue;

		strcpy(tmp, proc_fd);
		strcat(tmp, "/");
		strcat(tmp, dirent->d_name);

		status = readlink(tmp, path, PATH_MAX);
		if (status < 0 || status >= PATH_MAX)
			continue;
		path[status] = '\0';

		/* Ensure it points to a path (not a socket or somethink like that). */
		if (path[0] != '/')
			continue;

		status = callback(tracee, atoi(dirent->d_name), path);
		if (status < 0)
			goto end;
	}
	status = 0;

end:
	closedir(dirp);
	return status;
}

/**
 * Helper for list_open_fd().
 */
static int list_open_fd_callback(const Tracee *tracee, int fd, char path[PATH_MAX])
{
	VERBOSE(tracee, 1, "pid %d: access to \"%s\" (fd %d) won't be translated until closed",
		tracee->pid, path, fd);
	return 0;
}

/**
 * Warn for files that are open. It is useful right after PRoot has
 * attached a process.
 */
int list_open_fd(const Tracee *tracee)
{
	return foreach_fd(tracee, list_open_fd_callback);
}

/**
 * Substitute the first @old_prefix_length bytes of @path with
 * @new_prefix (the caller has to provides a correct
 * @new_prefix_length).  This function returns the new length of
 * @path.  Note: this function takes care about special cases (like
 * "/").
 */
size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_length,
			const char *new_prefix, size_t new_prefix_length)
{
	size_t path_length;
	size_t new_length;

	path_length = strlen(path);

	assert(old_prefix_length < PATH_MAX);
	assert(new_prefix_length < PATH_MAX);

	if (new_prefix_length == 1) {
		/* Special case: "/foo" -> "/".  Substitute "/foo/bin"
		 * with "/bin" not "//bin".  */

		new_length = path_length - old_prefix_length;
		if (new_length != 0)
			memmove(path, path + old_prefix_length, new_length);
		else {
			/* Special case: "/".  */
			path[0] = '/';
			new_length = 1;
		}
	}
	else if (old_prefix_length == 1) {
		/* Special case: "/" -> "/foo". Substitute "/bin" with
		 * "/foo/bin" not "/foobin".  */

		new_length = new_prefix_length + path_length;
		if (new_length >= PATH_MAX)
			return -ENAMETOOLONG;

		if (path_length > 1) {
			memmove(path + new_prefix_length, path, path_length);
			memcpy(path, new_prefix, new_prefix_length);
		}
		else {
			/* Special case: "/".  */
			memcpy(path, new_prefix, new_prefix_length);
			new_length = new_prefix_length;
		}
	}
	else {
		/* Generic case.  */

		new_length = path_length - old_prefix_length + new_prefix_length;
		if (new_length >= PATH_MAX)
			return -ENAMETOOLONG;

		memmove(path + new_prefix_length,
			path + old_prefix_length,
			path_length - old_prefix_length);
		memcpy(path, new_prefix, new_prefix_length);
	}

	assert(new_length < PATH_MAX);
	path[new_length] = '\0';

	return new_length;
}
