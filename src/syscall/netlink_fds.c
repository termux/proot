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

/*
 * Which descriptors of the tracees are the NETLINK_ROUTE sockets PRoot
 * emulates something about (see the AF_NETLINK helpers in enter.c).
 *
 * This follows the descriptor tables of the kernel, not the tracees:
 * the threads of a process share one table (clone(2) with CLONE_FILES),
 * so a socket one of them opens is known to all of them at once, and
 * any of them may read the reply to a request another one sent -- Go
 * moves goroutines from thread to thread, so syscall.NetlinkRIB() does
 * that all the time.  fork(2) copies the table, and execve(2) both
 * unshares it and closes the close-on-exec descriptors.
 *
 * The sockets themselves (NetlinkSocket) are shared by all the
 * descriptors that refer to them, in one table or another, like the
 * kernel shares an open file description.  Each entry of a table holds
 * one talloc link to its socket: the table the socket was created in
 * is its parent, every other entry holds a reference.  talloc_unlink()
 * drops either kind, handing the socket over to a remaining holder.
 *
 * Only close(2) is watched among the syscalls that change a descriptor
 * table: tracing dup(2), dup2(2), dup3(2) and fcntl(2) would cost every
 * process a ptrace stop for each of them -- shells and SQLite make a
 * lot -- whereas so few processes ever hold a netlink socket.  Instead,
 * the descriptor a netlink syscall is about is checked against the
 * inodes of the sockets, as long as its process holds any: a copy of
 * a socket is recognised there, and a descriptor that now refers to
 * another file is forgotten.
 */

#include <errno.h>     /* E*, errno, */
#include <stdio.h>     /* snprintf(3), sscanf(3), */
#include <unistd.h>    /* readlink(2), */
#include <talloc.h>    /* talloc_*, */

#include "syscall/netlink_fds.h"
#include "tracee/tracee.h"
#include "cli/note.h"

typedef struct netlink_fds {
	struct netlink_fd {
		int fd;
		NetlinkSocket *socket;
	} *entries;
	size_t nb_entries;
} NetlinkFds;

/**
 * Allocate an empty table for @tracee, see the fields "netlink_fds"
 * of Tracee.  This function returns NULL if an error occurred.
 */
struct netlink_fds *new_netlink_fds(Tracee *tracee)
{
	return talloc_zero(tracee, NetlinkFds);
}

/**
 * Put in @inode the inode of the socket behind the descriptor @fd of
 * the process @pid, or 0 if that descriptor refers to something else.
 * The link is only read, not followed: stat(2) would reach the file
 * itself, which may take a while, on a FUSE file system for instance.
 * This function returns -errno if an error occurred (-ENOENT: no such
 * descriptor), otherwise 0.
 */
static int fd_inode(pid_t pid, int fd, uint64_t *inode)
{
	char path[64];
	char link[64];
	unsigned long long value;
	char end;
	ssize_t size;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	size = readlink(path, link, sizeof(link) - 1);
	if (size < 0)
		return -errno;
	link[size] = '\0';

	*inode = (sscanf(link, "socket:[%llu%c", &value, &end) == 2 && end == ']')
		? (uint64_t) value : 0;
	return 0;
}

/**
 * Append the entry @fd -> @socket to @table, the caller having
 * established the link of this entry to @socket already.  This
 * function returns -errno if an error occurred, otherwise 0.
 */
static int add_entry(NetlinkFds *table, int fd, NetlinkSocket *socket)
{
	struct netlink_fd *entries;

	entries = talloc_realloc(table, table->entries, struct netlink_fd,
				 table->nb_entries + 1);
	if (entries == NULL)
		return -ENOMEM;

	entries[table->nb_entries].fd     = fd;
	entries[table->nb_entries].socket = socket;
	table->entries = entries;
	table->nb_entries++;

	return 0;
}

/**
 * Make the descriptor @fd of @table refer to @socket, which already
 * belongs to an entry of some table.  This function returns -errno if
 * an error occurred, otherwise 0.
 */
static int share_socket(NetlinkFds *table, int fd, NetlinkSocket *socket)
{
	if (talloc_reference(table, socket) == NULL)
		return -ENOMEM;

	if (add_entry(table, fd, socket) < 0) {
		(void) talloc_unlink(table, socket);
		return -ENOMEM;
	}

	return 0;
}

/**
 * Remove the @index-th entry of @table, and with it the socket once no
 * other descriptor refers to it: a reply the tracees never got round
 * to reading dies with its socket, as datagrams in a receive queue do.
 */
static void remove_entry(NetlinkFds *table, size_t index)
{
	NetlinkSocket *socket = table->entries[index].socket;

	table->entries[index] = table->entries[--table->nb_entries];
	(void) talloc_unlink(table, socket);
}

/**
 * Return the index of the entry of @fd in @table, or -1 if none.
 */
static ssize_t find_entry(const NetlinkFds *table, int fd)
{
	size_t i;

	if (fd < 0)
		return -1;

	for (i = 0; i < table->nb_entries; i++) {
		if (table->entries[i].fd == fd)
			return (ssize_t) i;
	}

	return -1;
}

/**
 * Return a copy of @from, allocated in @context, whose descriptors
 * refer to the same sockets.  This function returns NULL if an error
 * occurred.
 */
static NetlinkFds *copy_netlink_fds(const void *context, const NetlinkFds *from)
{
	NetlinkFds *table;
	size_t i;

	table = talloc_zero(context, NetlinkFds);
	if (table == NULL)
		return NULL;

	for (i = 0; i < from->nb_entries; i++) {
		if (share_socket(table, from->entries[i].fd, from->entries[i].socket) < 0) {
			talloc_free(table);
			return NULL;
		}
	}

	return table;
}

/**
 * Give the new @child of @parent the netlink sockets of its parent's
 * descriptors: the same table when they share it (@shared, that is
 * clone(CLONE_FILES)), otherwise a copy of it whose descriptors refer
 * to the same sockets, as after fork(2).  This function returns -errno
 * if an error occurred, otherwise 0.
 */
int inherit_netlink_fds(Tracee *child, Tracee *parent, bool shared)
{
	NetlinkFds *table;

	if (shared)
		table = talloc_reference(child, parent->netlink_fds);
	else
		table = copy_netlink_fds(child, parent->netlink_fds);
	if (table == NULL)
		return -ENOMEM;

	(void) talloc_unlink(child, child->netlink_fds);
	child->netlink_fds = table;

	return 0;
}

/**
 * Update the netlink sockets of @tracee after its successful execve(2):
 * the kernel unshared its descriptor table there, and closed the
 * close-on-exec descriptors without any close(2) PRoot could see.
 */
void unshare_netlink_fds_after_execve(Tracee *tracee)
{
	NetlinkFds *table = tracee->netlink_fds;
	size_t i;

	if (talloc_reference_count(table) > 0) {
		NetlinkFds *copy;

		copy = copy_netlink_fds(tracee, table);
		if (copy == NULL) {
			/* The table still belongs to the other tracees
			 * too, whose descriptors are all open: leave it
			 * as it is.  */
			note(tracee, WARNING, INTERNAL,
				"can't unshare the netlink sockets after execve");
			return;
		}

		(void) talloc_unlink(tracee, table);
		tracee->netlink_fds = table = copy;
	}

	/* Forget the descriptors that aren't open anymore, or that
	 * were made to refer to another file before execve(2) without
	 * PRoot knowing, close_range(2) then open(2) for instance.  A
	 * socket whose inode is unknown is kept as long as its
	 * descriptor can't be told to be closed.  */
	for (i = 0; i < table->nb_entries; ) {
		NetlinkSocket *socket = table->entries[i].socket;
		uint64_t inode = 0;
		int status;

		status = fd_inode(tracee->pid, table->entries[i].fd, &inode);
		if (   status == -ENOENT
		    || (status == 0 && socket->inode != 0 && inode != socket->inode)) {
			VERBOSE(tracee, 2, "netlink: fd %d closed by execve",
				table->entries[i].fd);
			remove_entry(table, i);
		}
		else
			i++;
	}
}

/**
 * Return the netlink socket the descriptor @fd of @tracee is known to
 * refer to, or NULL if PRoot emulates nothing about this descriptor.
 * See get_netlink_socket() for the descriptors made behind PRoot's
 * back.
 */
NetlinkSocket *netlink_socket(const Tracee *tracee, int fd)
{
	const NetlinkFds *table = tracee->netlink_fds;
	ssize_t index;

	index = find_entry(table, fd);
	if (index < 0)
		return NULL;

	return table->entries[index].socket;
}

/**
 * Return the netlink socket the descriptor @fd of @tracee refers to
 * right now, or NULL if PRoot emulates nothing about it.  Unlike
 * netlink_socket(), this recognises a copy of a known socket, made
 * with dup(2) & co., and forgets a descriptor that was made to refer
 * to another file, with dup2(2) for instance, or closed without
 * close(2).  It costs a readlink(2) of the descriptor, but only to the
 * tracees that hold a netlink socket.
 */
NetlinkSocket *get_netlink_socket(Tracee *tracee, int fd)
{
	NetlinkFds *table = tracee->netlink_fds;
	bool any_fake = false;
	uint64_t inode = 0;
	ssize_t index;
	int status;
	size_t i;

	if (table->nb_entries == 0 || fd < 0)
		return NULL;

	/* Real sockets matter only to the tracees that believe they
	 * own a network namespace (see handle_netlink_reply_exit), so
	 * don't make the others pay for the check.  */
	for (i = 0; i < table->nb_entries && !any_fake; i++)
		any_fake = table->entries[i].socket->fake;
	if (!any_fake && !tracee->fake_netns)
		return netlink_socket(tracee, fd);

	status = fd_inode(tracee->pid, fd, &inode);

	index = find_entry(table, fd);
	if (index >= 0) {
		NetlinkSocket *socket = table->entries[index].socket;

		if (   status == -ENOENT
		    || (status == 0 && socket->inode != 0 && inode != socket->inode)) {
			VERBOSE(tracee, 2, "netlink: fd %d isn't a netlink socket anymore", fd);
			remove_entry(table, (size_t) index);
		}
		else
			return socket;
	}

	if (status < 0 || inode == 0)
		return NULL;

	for (i = 0; i < table->nb_entries; i++) {
		NetlinkSocket *socket = table->entries[i].socket;

		if (socket->inode == 0 || socket->inode != inode)
			continue;

		VERBOSE(tracee, 2, "netlink: fd %d is a copy of fd %d",
			fd, table->entries[i].fd);

		if (share_socket(table, fd, socket) < 0)
			note(tracee, WARNING, INTERNAL, "can't track netlink socket %d", fd);

		return socket;
	}

	return NULL;
}

/**
 * Record that @tracee got the new NETLINK_ROUTE socket @fd, a @fake
 * one if PRoot substituted an AF_UNIX socket for it.  This function
 * returns NULL if an error occurred, otherwise the socket.
 */
NetlinkSocket *add_netlink_socket(Tracee *tracee, int fd, bool fake)
{
	NetlinkFds *table = tracee->netlink_fds;
	NetlinkSocket *socket;
	pid_t tgid, ppid, tracer;

	/* What PRoot knew about this descriptor number was closed
	 * meanwhile, without close(2).  */
	forget_netlink_fd(tracee, fd);

	socket = talloc_zero(table, NetlinkSocket);
	if (socket == NULL)
		return NULL;

	socket->fake = fake;

	if (fd_inode(tracee->pid, fd, &socket->inode) < 0)
		socket->inode = 0;

	/* The kernel binds the first netlink socket of a process to
	 * the id of the process, the thread group id.  */
	if (fake) {
		socket->port_id = (read_proc_status_ids(tracee->pid, &tgid, &ppid, &tracer) == 0)
				? (uint32_t) tgid
				: (uint32_t) tracee->pid;
	}

	if (add_entry(table, fd, socket) < 0) {
		talloc_free(socket);
		return NULL;
	}

	return socket;
}

/**
 * Forget the descriptor @fd of @tracee, it is being closed.
 */
void forget_netlink_fd(Tracee *tracee, int fd)
{
	NetlinkFds *table = tracee->netlink_fds;
	ssize_t index;

	index = find_entry(table, fd);
	if (index >= 0)
		remove_entry(table, (size_t) index);
}
