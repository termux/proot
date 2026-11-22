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

#ifndef NETLINK_FDS_H
#define NETLINK_FDS_H

#include <stdbool.h>   /* bool, */
#include <stddef.h>    /* size_t, */
#include <stdint.h>    /* uint*_t, */
#include <sys/types.h> /* ssize_t, */
#include <sys/socket.h> /* socklen_t, */
#include <sys/un.h>    /* struct sockaddr_un, */

#include "tracee/tracee.h"

/**
 * A NETLINK_ROUTE socket held by tracees, as far as PRoot emulates
 * something about it (see the AF_NETLINK helpers in enter.c).  As a
 * socket in the kernel, it outlives the descriptor that created it:
 * every descriptor that refers to it -- dup(2) copies, the copies a
 * fork(2) child inherits -- shares this one record, pending reply
 * included.
 */
typedef struct netlink_socket {
	/* Whether PRoot substituted an AF_UNIX socket for this one,
	 * the host denying AF_NETLINK: every netlink exchange on it is
	 * emulated then.  Otherwise it is a real socket, only watched
	 * for the ack emulation.  */
	bool fake;

	/* Inode of the socket (0 if unknown), to tell it from another
	 * file that got the same descriptor number later on, and to
	 * recognise the copies of its descriptor.  */
	uint64_t inode;

	/* Port id the kernel would have bound a fake socket to: the
	 * thread group id of its creator, no matter which thread
	 * asks, since callers check the replies they get against it
	 * (Go's syscall.NetlinkRIB, glibc, iproute2).  */
	uint32_t port_id;

	/* What PRoot synthesised for the latest request sent on a fake
	 * socket, waiting for the recvmsg / recvfrom that reads it.  It
	 * belongs to the socket since sockets have receive queues of
	 * their own: iproute2 walks a route dump on one of them while a
	 * second answers the interface lookups it makes along the way.
	 * The buffer is allocated on demand and handed back one
	 * datagram at a time ("reply_off" is how far the tracees have
	 * read), since that is how the kernel delivers a dump.  */
	uint8_t *reply;
	size_t reply_len;
	size_t reply_off;

	/* Socket of PRoot the substitute of a fake socket is connected
	 * to, -1 if none: what the tracees write(2) on their socket --
	 * the requests of busybox, for instance -- arrives there, and
	 * is read before any recvmsg / recvfrom is answered.  */
	int peer;

	/* For a real socket: a request that reconfigures a network
	 * namespace the sender only believes it owns went out on it,
	 * and the error the kernel replies with, to the sequence number
	 * below, has to become an ack (see handle_netlink_reply_exit).  */
	bool ack_pending;
	uint32_t ack_seq;
} NetlinkSocket;

#define MAX_FAKE_NETLINK_REPLY 8192

extern struct netlink_fds *new_netlink_fds(Tracee *tracee);
extern int inherit_netlink_fds(Tracee *child, Tracee *parent, bool shared);
extern void unshare_netlink_fds_after_execve(Tracee *tracee);

extern NetlinkSocket *netlink_socket(const Tracee *tracee, int fd);
extern NetlinkSocket *get_netlink_socket(Tracee *tracee, int fd);
extern NetlinkSocket *add_netlink_socket(Tracee *tracee, int fd, bool fake);
extern void forget_netlink_fd(Tracee *tracee, int fd);

extern int open_netlink_peer(NetlinkSocket *netlink, struct sockaddr_un *address,
			     socklen_t *length);
extern void close_netlink_peer(NetlinkSocket *socket);
extern ssize_t read_netlink_peer(NetlinkSocket *socket, void *buffer, size_t size);

#endif /* NETLINK_FDS_H */
