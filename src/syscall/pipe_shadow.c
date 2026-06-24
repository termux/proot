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
 * Shadow pipe read ends to prevent EPIPE for child writers.
 *
 * When a tracee closes the read end of an anonymous pipe and a child
 * process still holds the write end, ptrace serialisation causes the
 * parent to close first — leaving zero readers before the child writes.
 * The child's write() then returns EPIPE, causing bash to print
 * "Broken pipe" for process substitution (`echo <(echo a)`).
 *
 * The fix: at PR_close sysenter (before the fd is released), if the fd
 * is a pipe read end, proot opens its own reference via
 * /proc/<pid>/fd/<fd>.  This keeps the pipe alive so writers do not
 * get EPIPE.  We do NOT read from the shadow — the data remains in the
 * pipe buffer for any legitimate reader (diff, cat, …).  The shadow is
 * closed when poll(POLLHUP) fires, meaning all write ends are gone.
 */

#include <stdio.h>    /* snprintf, fopen, fgets, fclose */
#include <string.h>   /* strncmp */
#include <fcntl.h>    /* open, O_RDONLY, O_CLOEXEC */
#include <unistd.h>   /* readlink, close */
#include <poll.h>     /* poll, POLLHUP */
#include <sys/types.h>

#include "syscall/pipe_shadow.h"

#define MAX_SHADOW_PIPES 32

static int shadow_fds[MAX_SHADOW_PIPES];
static int shadow_fds_initialised;

static void ensure_init(void)
{
	int i;

	if (shadow_fds_initialised)
		return;
	for (i = 0; i < MAX_SHADOW_PIPES; i++)
		shadow_fds[i] = -1;
	shadow_fds_initialised = 1;
}

void shadow_pipe_read_end(pid_t tracee_pid, int tracee_fd)
{
	char path[64];
	char link[32];
	char line[128];
	ssize_t len;
	unsigned long flags;
	FILE *f;
	int shadow_fd;
	int i;

	ensure_init();

	/* Check the fd is an anonymous pipe. */
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", tracee_pid, tracee_fd);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		return;
	link[len] = '\0';
	if (strncmp(link, "pipe:[", 6) != 0)
		return;

	/* Confirm it is the read end (flags O_RDONLY = 0 in O_ACCMODE). */
	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", tracee_pid, tracee_fd);
	f = fopen(path, "r");
	if (!f)
		return;
	flags = 1; /* default: not O_RDONLY */
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "flags:", 6) == 0) {
			sscanf(line + 6, " %lo", &flags);
			break;
		}
	}
	fclose(f);
	if ((flags & O_ACCMODE) != O_RDONLY)
		return;

	/* Find a free slot. */
	for (i = 0; i < MAX_SHADOW_PIPES; i++) {
		if (shadow_fds[i] == -1)
			break;
	}
	if (i == MAX_SHADOW_PIPES)
		return; /* No room; skip silently. */

	/* Open shadow reference before the tracee's close() executes.
	 * We do NOT set O_NONBLOCK: we never read from this fd, we just
	 * hold it open so the pipe's read-end reference count stays > 0.  */
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", tracee_pid, tracee_fd);
	shadow_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (shadow_fd >= 0)
		shadow_fds[i] = shadow_fd;
}

void shadow_pipes_close_eof(void)
{
	struct pollfd pfd;
	int i;

	if (!shadow_fds_initialised)
		return;

	for (i = 0; i < MAX_SHADOW_PIPES; i++) {
		if (shadow_fds[i] < 0)
			continue;

		/* POLLHUP on a pipe read end fires when all write ends
		 * are closed (no more writers).  poll with timeout 0 is
		 * non-blocking.  */
		pfd.fd     = shadow_fds[i];
		pfd.events = 0; /* interested in POLLHUP only */
		pfd.revents = 0;

		if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLHUP)) {
			close(shadow_fds[i]);
			shadow_fds[i] = -1;
		}
	}
}
