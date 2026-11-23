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

#include <stddef.h>      /* offsetof(3), */
#include <strings.h>     /* bzero(3), */
#include <string.h>      /* strncpy(3), strlen(3), */
#include <assert.h>      /* assert(3), */
#include <errno.h>       /* E*, */
#include <sys/socket.h>  /* struct sockaddr_un, AF_UNIX, */
#include <sys/un.h>      /* struct sockaddr_un, */
#include <sys/param.h>   /* MIN(), MAX(), */
#include <sys/stat.h>    /* lstat(2), S_ISSOCK(), */
#include <unistd.h>      /* unlink(2), */
#include <sys/uio.h>     /* UIO_MAXIOV, */
#include <linux/net.h>   /* SYS_*, */
#include <stdint.h>      /* uint8_t, uint32_t, int32_t, */
#include <talloc.h>      /* talloc_*, */

#include "syscall/socket.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/binding.h"
#include "path/temp.h"
#include "path/path.h"
#include "cli/note.h"
#include "arch.h"

#include "compat.h"

/* The sockaddr_un structure has exactly the same layout on all
 * architectures.  */
static const off_t offsetof_path = offsetof(struct sockaddr_un, sun_path);
extern struct sockaddr_un sockaddr_un__;
static const size_t sizeof_path  = sizeof(sockaddr_un__.sun_path);

/**
 * Copy in @sockaddr the struct sockaddr_un stored in the @tracee
 * memory at the given @address.  Also, its pathname is copied to the
 * null-terminated @path.  Only @size bytes are read from the @tracee
 * memory (should be <= @max_size <= sizeof(struct sockaddr_un)).
 * This function returns -errno if an error occurred, 0 if the
 * structure was not found (not a sockaddr_un or @size > @max_size),
 * otherwise 1.
 */
static int read_sockaddr_un(Tracee *tracee, struct sockaddr_un *sockaddr, word_t max_size,
			char path[PATH_MAX], word_t address, int size)
{
	int status;

	assert(max_size <= sizeof(struct sockaddr_un));

	/* Nothing to do if the sockaddr has an unexpected size.  */
	if (size <= offsetof_path || (word_t) size > max_size)
		return 0;

	bzero(sockaddr, sizeof(struct sockaddr_un));
	status = read_data(tracee, sockaddr, address, size);
	if (status < 0)
		return status;

	/* Nothing to do if it's not a named Unix domain socket.  */
	if ((sockaddr->sun_family != AF_UNIX)
	    || sockaddr->sun_path[0] == '\0')
		return 0;

	/* Be careful: sun_path doesn't have to be null-terminated.  */
	assert(sizeof_path < PATH_MAX - 1);
	strncpy(path, sockaddr->sun_path, sizeof_path);
	path[sizeof_path] = '\0';

	return 1;
}

/**
 * Push a copy of @sockaddr whose pathname is replaced with
 * @host_path to a newly allocated space in the @tracee memory, and put
 * its address in the @address parameter.  This function returns
 * -errno if an error occurred, otherwise 1.
 */
static int push_sockaddr_un(Tracee *tracee, struct sockaddr_un *sockaddr,
			const char *host_path, word_t *address)
{
	int status;

	strncpy(sockaddr->sun_path, host_path, sizeof_path);

	/* Push the updated sockaddr to a newly allocated space.  */
	*address = alloc_mem(tracee, sizeof(*sockaddr));
	if (*address == 0)
		return -EFAULT;

	status = write_data(tracee, *address, sockaddr, sizeof(*sockaddr));
	if (status < 0)
		return status;

	return 1;
}

/**
 * A symbolic link PRoot made in its temporary directory to a host path
 * too long to fit the sun_path array, see shorten_socket_path().
 */
typedef struct SocketAlias {
	char *path;   /* "<temporary directory>/proot-XXXXXX".  */
	char *target; /* The host path it leads to.  */
	struct SocketAlias *next;
} SocketAlias;

/* All the aliases made so far, the most recent first.  They live as
 * long as PRoot does, as the sockets bound through them might do: the
 * kernel reports the path a socket was bound to as it was given.  */
static SocketAlias *socket_aliases = NULL;

/**
 * Return whether the alias @alias still leads to its target: anyone
 * may have removed it, as the guest cleaning its "/tmp" up when it is
 * the temporary directory of PRoot.
 */
static bool is_socket_alias_intact(const SocketAlias *alias)
{
	char target[PATH_MAX];
	ssize_t length;

	length = readlink(alias->path, target, sizeof(target));
	return length >= 0
		&& (size_t) length == strlen(alias->target)
		&& memcmp(target, alias->target, length) == 0;
}

/**
 * Remove the alias @alias, unless it was replaced with another file.
 *
 * Note: this is a talloc destructor.
 */
static int remove_socket_alias(SocketAlias *alias)
{
	if (is_socket_alias_intact(alias) && unlink(alias->path) < 0)
		note(NULL, WARNING, SYSTEM, "can't remove '%s'", alias->path);

	return 0;
}

/**
 * Return the length of the path of the aliases (see get_socket_alias()).
 */
static size_t get_socket_alias_length()
{
	return strlen(get_temp_directory()) + strlen("/proot-XXXXXX");
}

/**
 * Return the path of an alias of the host path @target, that is, a
 * symbolic link to it, made unless there's one already.  This
 * function returns NULL and sets errno if an error occurred.
 */
static const char *get_socket_alias(const char *target)
{
	SocketAlias *alias;
	int saved_errno;
	int status = -1;
	int i;

	/* Only the most recent alias of @target is worth a try.  */
	for (alias = socket_aliases; alias != NULL; alias = alias->next) {
		if (strcmp(alias->target, target) != 0)
			continue;

		if (is_socket_alias_intact(alias))
			return alias->path;
		break;
	}

	alias = talloc_zero(talloc_autofree_context(), SocketAlias);
	if (alias == NULL)
		goto no_memory;

	alias->target = talloc_strdup(alias, target);
	alias->path   = talloc_asprintf(alias, "%s/proot-XXXXXX", get_temp_directory());
	if (alias->target == NULL || alias->path == NULL)
		goto no_memory;

	/* Like mkstemp(3), but for a symbolic link.  */
	for (i = 0; i < 100; i++) {
		strcpy(alias->path + strlen(alias->path) - strlen("XXXXXX"), "XXXXXX");
		(void) mktemp(alias->path);
		if (alias->path[0] == '\0') {
			errno = EEXIST;
			break;
		}

		status = symlink(target, alias->path);
		if (status == 0 || errno != EEXIST)
			break;
	}

	if (status < 0) {
		saved_errno = errno;
		note(NULL, WARNING, SYSTEM, "can't create a symbolic link in '%s'",
			get_temp_directory());
		talloc_free(alias);
		errno = saved_errno;
		return NULL;
	}

	talloc_set_destructor(alias, remove_socket_alias);

	alias->next = socket_aliases;
	socket_aliases = alias;

	return alias->path;

no_memory:
	talloc_free(alias);
	errno = ENOMEM;
	return NULL;
}

/**
 * Replace in @path the alias it starts with, if any, with the host
 * path this latter leads to.  This function returns -errno if an
 * error occurred, otherwise 0.
 */
static int expand_socket_alias(char path[PATH_MAX])
{
	char expanded_path[PATH_MAX];
	const SocketAlias *alias;
	size_t length;
	int status;

	for (alias = socket_aliases; alias != NULL; alias = alias->next) {
		length = strlen(alias->path);
		if (   strncmp(path, alias->path, length) != 0
		    || (path[length] != '/' && path[length] != '\0'))
			continue;

		status = snprintf(expanded_path, sizeof(expanded_path), "%s%s",
				alias->target, path + length);
		if (status < 0 || (size_t) status >= sizeof(expanded_path))
			return -ENAMETOOLONG;

		strcpy(path, expanded_path);
		return 0;
	}

	return 0;
}

/**
 * Replace the host @path, too long to fit the sun_path array, with a
 * shorter one that leads to the same place: the kernel resolves both
 * the same way, the socket is where the guest expects it and nothing
 * else changes for the guest.  This shorter path is made of an alias
 * of the directory of the final component (see get_socket_alias())
 * followed by this component, or, if this doesn't fit sun_path either,
 * of an alias of @path itself, provided the kernel follows this final
 * symbolic link, as stated by @follow_final.  Unlike the guest, PRoot
 * leaves room for the terminating null byte: the kernel reports the
 * address of a socket bound to a path that fills sun_path as longer
 * than struct sockaddr_un, which translate_socketcall_exit() leaves
 * as is.  This function returns -errno if an error occurred, 0 if
 * @path was left as is because it can't be shortened, otherwise 1.
 */
static int shorten_socket_path(char path[PATH_MAX], bool follow_final)
{
	const size_t alias_length = get_socket_alias_length();
	char directory[PATH_MAX];
	const char *alias;
	size_t final;
	size_t length;
	int status;

	/* The final component starts at path[final], it goes along
	 * with its trailing "/", if any.  */
	length = strlen(path);
	final  = length;
	while (final > 0 && path[final - 1] == '/')
		final--;
	while (final > 0 && path[final - 1] != '/')
		final--;

	if (final > 0 && alias_length + 1 + strlen(path + final) < sizeof_path) {
		/* path[final - 1] is the "/" before the final
		 * component, the one of "/" itself is kept.  */
		memcpy(directory, path, final);
		directory[final > 1 ? final - 1 : 1] = '\0';

		alias = get_socket_alias(directory);
		if (alias == NULL)
			return -errno;

		memmove(path + alias_length + 1, path + final, strlen(path + final) + 1);
		memcpy(path, alias, alias_length);
		path[alias_length] = '/';
		return 1;
	}

	if (!follow_final || alias_length >= sizeof_path)
		return 0;

	alias = get_socket_alias(path);
	if (alias == NULL)
		return -errno;

	status = snprintf(path, PATH_MAX, "%s", alias);
	assert(status >= 0 && (size_t) status == alias_length);

	return 1;
}

/**
 * Remove the socket that lies at the shorter host @path, if any.  A
 * file of another type was put there by the tracees through the
 * binding, it is theirs.
 *
 * Note: this is a talloc destructor.
 */
static int remove_shorter_host_path(char *path)
{
	struct stat statl;
	int status;

	status = lstat(path, &statl);
	if (status < 0 || !S_ISSOCK(statl.st_mode))
		return 0;

	status = unlink(path);
	if (status < 0)
		note(NULL, WARNING, SYSTEM, "can't remove '%s'", path);

	return 0;
}

/**
 * Translate the pathname of the struct sockaddr_un currently stored
 * in the @tracee memory at the given @address, for bind(2) if
 * @is_bind, otherwise for connect(2).  See the documentation of
 * read_sockaddr_un() for the meaning of the @size parameter.  Also,
 * the new address of the translated sockaddr_un is put in the
 * @address parameter.  This function returns -errno if an error
 * occurred, 0 if there was nothing to translate, otherwise 1.
 */
int translate_socketcall_enter(Tracee *tracee, word_t *address, int size, bool is_bind)
{
	struct sockaddr_un sockaddr;
	char user_path[PATH_MAX];
	char host_path[PATH_MAX];
	int status;

	if (*address == 0)
		return 0;

	status = read_sockaddr_un(tracee, &sockaddr, sizeof(sockaddr), user_path, *address, size);
	if (status <= 0)
		return status;

	status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);
	if (status < 0)
		return status;

	/* Be careful: sun_path doesn't have to be null-terminated.  */
	if (strlen(host_path) > sizeof_path) {
		status = shorten_socket_path(host_path, !is_bind);
		if (status < 0)
			return status;
		if (status == 0 && !is_bind)
			return -EINVAL;
	}

	/* Only bind(2) gets there, when the final component is too
	 * long for an alias of its directory: the kernel would make the
	 * socket at the alias itself, not where it leads.  */
	if (strlen(host_path) > sizeof_path) {
		char *shorter_host_path;
		Binding *binding;

		/* So let's bind the guest path to a shorter path, where
		 * the socket is made instead.  Unlike an alias, this
		 * binding stands for this guest path in all cases: it is
		 * not removed along with the socket.  The socket bound
		 * there, if any, is removed when PRoot exits rather than
		 * with this binding: the copies of the bindings made for
		 * a child that asked for a mount name-space of its own
		 * still lead there.  */
		shorter_host_path = create_temp_name(NULL, "proot");
		if (shorter_host_path == NULL)
			return -EINVAL;

		(void) mktemp(shorter_host_path);

		if (strlen(shorter_host_path) > sizeof_path) {
			TALLOC_FREE(shorter_host_path);
			return -EINVAL;
		}

		/* Ensure the guest path of this new binding is
		 * canonicalized, as it is always assumed.  */
		strcpy(user_path, host_path);
		status = detranslate_path(tracee, user_path, NULL);
		if (status < 0) {
			TALLOC_FREE(shorter_host_path);
			return -EINVAL;
		}

		/* Bing the guest path to a shorter host path.  */
		binding = insort_binding3(tracee, tracee->ctx, shorter_host_path, user_path);
		if (binding == NULL) {
			TALLOC_FREE(shorter_host_path);
			return -EINVAL;
		}

		talloc_set_destructor(shorter_host_path, remove_shorter_host_path);

		/* Let's use this shorter path now.  */
		strcpy(host_path, shorter_host_path);
	}

	return push_sockaddr_un(tracee, &sockaddr, host_path, address);
}

/**
 * Translate the pathname of the struct sockaddr_un currently stored
 * in the @tracee memory at the given @address (@size bytes long), the
 * destination of a message sent by sendto(2), sendmsg(2) or
 * sendmmsg(2).  It is translated like the address connect(2) is
 * given, except when nothing exists at this absolute path in the guest
 * namespace: the address is left as is then.  Addresses the kernel
 * reports, like the source of a datagram given by recvfrom(2), name
 * host paths: a reply sent to one of them has to reach it.
 *
 * The new address of the translated sockaddr_un is put in the
 * @address parameter.  This function returns -errno if an error
 * occurred, 0 if the address was left as is, otherwise 1.
 */
int translate_send_address(Tracee *tracee, word_t *address, int size)
{
	struct sockaddr_un sockaddr;
	char user_path[PATH_MAX];
	char host_path[PATH_MAX];
	struct stat statl;
	int saved_errno;
	int status;

	if (*address == 0)
		return 0;

	status = read_sockaddr_un(tracee, &sockaddr, sizeof(sockaddr), user_path, *address, size);
	if (status <= 0)
		return status;

	status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);

	/* Only an absolute path can be a host path the kernel reported:
	 * bind(2) gives it the absolute host path of the sockets the
	 * tracees bind, possibly through an alias (see
	 * shorten_socket_path()).  A relative path is always resolved
	 * against the guest working directory, the kernel tells whether
	 * something exists there.  */
	if (status == 0 && user_path[0] == '/') {
		saved_errno = errno;
		if (lstat(host_path, &statl) < 0 && (errno == ENOENT || errno == ENOTDIR))
			status = -errno;
		errno = saved_errno;
	}

	if ((status == -ENOENT || status == -ENOTDIR) && user_path[0] == '/')
		return 0;

	if (status < 0)
		return status;

	/* Be careful: sun_path doesn't have to be null-terminated.  */
	if (strlen(host_path) > sizeof_path) {
		status = shorten_socket_path(host_path, true);
		if (status < 0)
			return status;
		if (status == 0)
			return -ENAMETOOLONG;
	}

	return push_sockaddr_un(tracee, &sockaddr, host_path, address);
}

/* A struct msghdr is seven words long, msg_name being the first one
 * and msg_namelen the second one, and a struct mmsghdr is a struct
 * msghdr followed by msg_len, eight words long, on all ABIs.  */
#define SIZEOF_MSGHDR(tracee)	(7 * sizeof_word(tracee))
#define SIZEOF_MMSGHDR(tracee)	(8 * sizeof_word(tracee))

/**
 * Return the word stored in the copy of @tracee memory at @data.
 */
static word_t get_word(const Tracee *tracee, const uint8_t *data)
{
	uint32_t value32;
	word_t value;

	if (sizeof_word(tracee) == sizeof(value32)) {
		memcpy(&value32, data, sizeof(value32));
		return value32;
	}

	memcpy(&value, data, sizeof(value));
	return value;
}

/**
 * Store @value as a word in the copy of @tracee memory at @data.
 */
static void set_word(const Tracee *tracee, uint8_t *data, word_t value)
{
	uint32_t value32 = value;

	if (sizeof_word(tracee) == sizeof(value32))
		memcpy(data, &value32, sizeof(value32));
	else
		memcpy(data, &value, sizeof(value));
}

/**
 * Translate the destination of the struct msghdr whose copy is at
 * @msghdr, see translate_send_address().  This function returns
 * -errno if an error occurred, 0 if the copy was left as is,
 * otherwise 1.
 */
static int translate_msg_name(Tracee *tracee, uint8_t *msghdr)
{
	const size_t offsetof_namelen = sizeof_word(tracee);
	int32_t namelen;
	word_t name;
	int status;

	name = get_word(tracee, msghdr);
	memcpy(&namelen, msghdr + offsetof_namelen, sizeof(namelen));

	status = translate_send_address(tracee, &name, namelen);
	if (status <= 0)
		return status;

	namelen = sizeof(struct sockaddr_un);
	set_word(tracee, msghdr, name);
	memcpy(msghdr + offsetof_namelen, &namelen, sizeof(namelen));

	return 1;
}

/**
 * Push a copy of the @size bytes at @data to a newly allocated space
 * in the @tracee memory, and put its address in the @address
 * parameter.  This function returns -errno if an error occurred,
 * otherwise 0.
 */
static int push_data(Tracee *tracee, const void *data, size_t size, word_t *address)
{
	*address = alloc_mem(tracee, size);
	if (*address == 0)
		return -EFAULT;

	return write_data(tracee, *address, data, size);
}

/**
 * Translate the destination of the struct msghdr currently stored in
 * the @tracee memory at the given @address, see
 * translate_send_address().  The tracee might use its structure
 * again, so it is left untouched: the address of an updated copy is
 * put in the @address parameter instead.  This function returns
 * -errno if an error occurred, 0 if nothing was changed, otherwise 1.
 */
int translate_sendmsg_enter(Tracee *tracee, word_t *address)
{
	uint8_t msghdr[7 * sizeof(word_t)];
	const size_t size = SIZEOF_MSGHDR(tracee);
	int status;

	if (*address == 0)
		return 0;

	/* Let the kernel report a bad address.  */
	status = read_data(tracee, msghdr, *address, size);
	if (status < 0)
		return 0;

	status = translate_msg_name(tracee, msghdr);
	if (status <= 0)
		return status;

	status = push_data(tracee, msghdr, size, address);
	if (status < 0)
		return status;

	return 1;
}

/**
 * Translate the destination of each of the *@vlen struct mmsghdr
 * currently stored in the @tracee memory at the given @address, see
 * translate_send_address().  As with translate_sendmsg_enter(), the
 * address of an updated copy of this vector is put in the @address
 * parameter when a destination is translated: the kernel reports the
 * number of bytes sent for each message in this copy, see
 * translate_sendmmsg_exit().  Like the kernel, only the messages that
 * precede the first one that can't be sent are sent: *@vlen is
 * lowered to their number, or the error is returned if there's none.
 * This function returns -errno if an error occurred, 0 if nothing
 * was changed, otherwise 1.
 */
int translate_sendmmsg_enter(Tracee *tracee, word_t *address, word_t *vlen)
{
	const size_t size = SIZEOF_MMSGHDR(tracee);
	bool translated = false;
	uint8_t *vector;
	word_t count;
	word_t i;
	int status = 0;

	if (*address == 0 || *vlen == 0)
		return 0;

	/* The kernel doesn't send more messages at once.  */
	count = MIN(*vlen, UIO_MAXIOV);

	vector = talloc_size(tracee->ctx, count * size);
	if (vector == NULL)
		return -ENOMEM;

	/* Let the kernel report a bad address.  */
	status = read_data(tracee, vector, *address, count * size);
	if (status < 0)
		return 0;

	for (i = 0; i < count; i++) {
		status = translate_msg_name(tracee, vector + i * size);
		if (status < 0)
			break;
		if (status > 0)
			translated = true;
	}

	if (status < 0) {
		if (i == 0)
			return status;
		count = i;
	}
	else if (!translated)
		return 0;

	*vlen = count;

	if (translated) {
		status = push_data(tracee, vector, count * size, address);
		if (status < 0)
			return status;
	}

	return 1;
}

/**
 * Report to the vector of struct mmsghdr stored in the @tracee memory
 * at the given @address the number of bytes the kernel sent for each
 * of its first @count messages, written in the copy of this vector at
 * @copy, see translate_sendmmsg_enter().  This function returns
 * -errno if an error occurred, otherwise 0.
 */
int translate_sendmmsg_exit(Tracee *tracee, word_t address, word_t copy, word_t count)
{
	const size_t offsetof_len = SIZEOF_MSGHDR(tracee);
	const size_t size = SIZEOF_MMSGHDR(tracee);
	uint32_t length;
	word_t i;

	for (i = 0; i < count; i++) {
		length = peek_uint32(tracee, copy + i * size + offsetof_len);
		if (errno != 0)
			return -errno;

		poke_uint32(tracee, address + i * size + offsetof_len, length);
		if (errno != 0)
			return -errno;
	}

	return 0;
}

/**
 * Translate the destination(s) of the sendto(2), sendmsg(2) or
 * sendmmsg(2) the @tracee is making through socketcall(2), as
 * specified by @call, with the arguments currently stored in its
 * memory at the given @address.  These arguments are left untouched:
 * the address of an updated copy is put in the @address parameter
 * instead.  This function returns -errno if an error occurred, 0 if
 * nothing was changed, otherwise 1.
 */
int translate_socketcall_send_enter(Tracee *tracee, word_t call, word_t *address)
{
	const size_t word_size = sizeof_word(tracee);
	uint8_t args[6 * sizeof(word_t)];
	size_t nb_args;
	word_t value1;
	word_t value2;
	int status;

	switch (call) {
	case SYS_SENDTO:
		nb_args = 6;
		break;

	case SYS_SENDMSG:
		nb_args = 3;
		break;

	case SYS_SENDMMSG:
		nb_args = 4;
		break;

	default:
		return 0;
	}

	/* Let the kernel report a bad address.  */
	status = read_data(tracee, args, *address, nb_args * word_size);
	if (status < 0)
		return 0;

	switch (call) {
	case SYS_SENDTO:
		/* int sendto(int, const void *, size_t, int,
		 *            const struct sockaddr *, socklen_t)  */
		value1 = get_word(tracee, args + 4 * word_size);
		status = translate_send_address(tracee, &value1,
						(int) get_word(tracee, args + 5 * word_size));
		if (status <= 0)
			return status;

		set_word(tracee, args + 4 * word_size, value1);
		set_word(tracee, args + 5 * word_size, sizeof(struct sockaddr_un));
		break;

	case SYS_SENDMSG:
		/* ssize_t sendmsg(int, const struct msghdr *, int)  */
		value1 = get_word(tracee, args + 1 * word_size);
		status = translate_sendmsg_enter(tracee, &value1);
		if (status <= 0)
			return status;

		set_word(tracee, args + 1 * word_size, value1);
		break;

	case SYS_SENDMMSG:
		/* int sendmmsg(int, struct mmsghdr *, unsigned int, int)  */
		value1 = get_word(tracee, args + 1 * word_size);
		value2 = (unsigned int) get_word(tracee, args + 2 * word_size);
		status = translate_sendmmsg_enter(tracee, &value1, &value2);
		if (status <= 0)
			return status;

		set_word(tracee, args + 1 * word_size, value1);
		set_word(tracee, args + 2 * word_size, value2);
		break;
	}

	status = push_data(tracee, args, nb_args * word_size, address);
	if (status < 0)
		return status;

	return 1;
}

/**
 * Detranslate the pathname of the struct sockaddr_un currently stored
 * in the @tracee memory at the given @sock_addr.  See the
 * documentation of read_sockaddr_un() for the meaning of the
 * @size_addr and @max_size parameters.  This function returns -errno
 * if an error occurred, otherwise 0.
 */
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size)
{
	struct sockaddr_un sockaddr;
	bool is_truncated = false;
	char path[PATH_MAX];
	int status;
	int size;

	if (sock_addr == 0)
		return 0;

	size = peek_int32(tracee, size_addr);
	if (errno != 0)
		return -errno;

	max_size = MIN(max_size, sizeof(sockaddr));
	status = read_sockaddr_un(tracee, &sockaddr, max_size, path, sock_addr, size);
	if (status <= 0)
		return status;

	/* The socket was bound through an alias, see
	 * shorten_socket_path().  */
	status = expand_socket_alias(path);
	if (status < 0)
		return status;

	status = detranslate_path(tracee, path, NULL);
	if (status < 0)
		return status;

	/* Be careful: sun_path doesn't have to be null-terminated.  */
	size = offsetof_path + strlen(path) + 1;
	if (size < 0 || (word_t) size > max_size) {
		size = max_size;
		is_truncated = true;
	}
	strncpy(sockaddr.sun_path, path, sizeof_path);

	/* Overwrite the sockaddr and socklen parameters.  */
	status = write_data(tracee, sock_addr, &sockaddr, size);
	if (status < 0)
		return status;

	/* If sockaddr is truncated (because the buffer provided is
	 * too small), addrlen will return a value greater than was
	 * supplied to the call.  See man 2 accept. */
	if (is_truncated)
		size = max_size + 1;

	poke_int32(tracee, size_addr, size);
	if (errno != 0)
		return -errno;

	return 0;
}
