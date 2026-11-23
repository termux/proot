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
 * The fix: at the exit stage of pipe(2) and pipe2(2), proot opens its
 * own reference to the new read end via /proc/<pid>/fd/<fd>.  This
 * keeps the pipe alive so writers do not get EPIPE.  We do NOT read
 * from the shadow — the data remains in the pipe buffer for any
 * legitimate reader (diff, cat, …).  As long as the tracees hold read
 * ends of their own, the shadow changes nothing.
 *
 * The shadow is taken when the pipe is created rather than when its
 * read end is closed: nearly every open(2) is followed by a close(2),
 * stopping the tracees at each of them would slow everything down,
 * whereas pipes are created seldom.  And the race happens right after
 * the creation of the pipe: a shell closes its copy of the read end
 * as soon as it has forked the processes of a pipeline or of a
 * process substitution.
 *
 * A shadow only papers over a scheduling race, so it must not outlive
 * it: holding one forever hands the guest a reader that never reads,
 * which deadlocks writers producing more than the pipe can buffer
 * (`yes | head -1`, mandb decompressing a large manual page — the
 * reader closes early, the writer then blocks in write() instead of
 * dying from EPIPE, and whoever wait()s on it waits forever).  A
 * shadow is therefore released as soon as it can no longer help: all
 * write ends are gone (POLLHUP), the pipe is too full for a writer to
 * make progress, or the race it was opened for is long over.
 *
 * Dropping a shadow is always safe: it is a bonus reference, real
 * readers hold their own.  The only risk of dropping one too early is
 * losing the race again, hence the checks below rather than a plain
 * timeout.
 */

#include <stdio.h>    /* snprintf */
#include <string.h>   /* strncmp */
#include <strings.h>  /* bzero */
#include <fcntl.h>    /* open, fcntl, O_RDONLY, O_CLOEXEC, F_GETPIPE_SZ */
#include <unistd.h>   /* readlink, close */
#include <poll.h>     /* poll, POLLHUP */
#include <stdbool.h>  /* bool, true, false */
#include <limits.h>   /* PIPE_BUF */
#include <time.h>     /* clock_gettime(2), CLOCK_MONOTONIC */
#include <sys/ioctl.h> /* ioctl(2), FIONREAD */
#include <sys/time.h>  /* setitimer(2), ITIMER_REAL */
#include <sys/types.h>

#include "syscall/pipe_shadow.h"

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

#ifndef FIONREAD
#define FIONREAD 0x541B
#endif

#define MAX_SHADOW_PIPES 32

/* The racing writer runs within a fraction of a second of the creation
 * of its pipe, even with every one of its syscalls stopping for proot.
 * Past this point a shadow protects nothing, it only keeps a pipe
 * artificially alive.  */
#define SHADOW_MAX_AGE_MS 1000

/* How often the event loop wakes up to run shadow_pipes_reap() while
 * shadows are held; bounds how long a blocked writer waits for the
 * EPIPE it would have gotten right away without proot.  */
#define SHADOW_TIMER_MS 50

/* shadow_pipes_reap() is called on every tracee event, far more often
 * than a pipe can change state.  Rate-limit the per-shadow probing to
 * one round per this many milliseconds -- comfortably below the timer
 * above, so a tick never finds itself skipped.  */
#define SHADOW_REAP_INTERVAL_MS (SHADOW_TIMER_MS / 2)

typedef struct {
	int fd;			/* -1 when the slot is free */
	struct timespec birth;
} Shadow;

static Shadow shadows[MAX_SHADOW_PIPES];
static int shadows_initialised;
static int shadows_held;

static void ensure_init(void)
{
	int i;

	if (shadows_initialised)
		return;
	for (i = 0; i < MAX_SHADOW_PIPES; i++)
		shadows[i].fd = -1;
	shadows_initialised = 1;
}

static void release_shadow(int slot)
{
	close(shadows[slot].fd);
	shadows[slot].fd = -1;
	shadows_held--;
}

/**
 * Return the number of milliseconds elapsed since @since.
 */
static long elapsed_ms(const struct timespec *since)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;

	return (now.tv_sec - since->tv_sec) * 1000
	     + (now.tv_nsec - since->tv_nsec) / 1000000;
}

/**
 * Return true when @fd's pipe holds too much data for a writer to make
 * progress.  Any blocked writer implies this: the kernel requires
 * writes of up to PIPE_BUF bytes to land atomically, so it parks the
 * writer as soon as that much room is missing.  The converse may be a
 * false positive (the writer might not be blocked, or might not even
 * exist), which is harmless — see the note on dropping shadows above.
 */
static bool writer_would_block(int fd)
{
	int buffered;
	int capacity;

	capacity = fcntl(fd, F_GETPIPE_SZ);
	if (capacity <= 0)
		return false;

	if (ioctl(fd, FIONREAD, &buffered) < 0)
		return false;

	/* A pipe smaller than PIPE_BUF (the kernel falls back to a
	 * single page once the user's pipe quota is exhausted) can only
	 * be reported full.  Requiring data to be buffered still keeps
	 * the shadow for the whole window that matters: as long as the
	 * racing writer has not written, the pipe is empty.  */
	return buffered > (capacity > PIPE_BUF ? capacity - PIPE_BUF : 0);
}

void shadow_new_pipe(pid_t tracee_pid, int read_fd)
{
	char path[64];
	char link[32];
	ssize_t len;
	int shadow_fd;
	int i;

	ensure_init();

	/* Check the fd is still an anonymous pipe: another thread may
	 * have reused it already.  Opening it doesn't block then, unlike
	 * opening a FIFO.  */
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", tracee_pid, read_fd);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		return;
	link[len] = '\0';
	if (strncmp(link, "pipe:[", 6) != 0)
		return;

	/* Find a free slot. */
	for (i = 0; i < MAX_SHADOW_PIPES; i++) {
		if (shadows[i].fd == -1)
			break;
	}
	if (i == MAX_SHADOW_PIPES)
		return; /* No room; skip silently. */

	/* We do NOT set O_NONBLOCK: we never read from this fd, we just
	 * hold it open so the pipe's read-end reference count stays > 0.  */
	shadow_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (shadow_fd < 0)
		return;

	shadows[i].fd = shadow_fd;
	if (clock_gettime(CLOCK_MONOTONIC, &shadows[i].birth) < 0)
		bzero(&shadows[i].birth, sizeof(shadows[i].birth));
	shadows_held++;
}

void shadow_pipes_reap(void)
{
	static struct timespec last_reap;
	struct pollfd pfd;
	int i;

	if (shadows_held == 0)
		return;

	if (elapsed_ms(&last_reap) < SHADOW_REAP_INTERVAL_MS)
		return;
	if (clock_gettime(CLOCK_MONOTONIC, &last_reap) < 0)
		bzero(&last_reap, sizeof(last_reap));

	for (i = 0; i < MAX_SHADOW_PIPES; i++) {
		if (shadows[i].fd < 0)
			continue;

		/* POLLHUP on a pipe read end fires when all write ends
		 * are closed (no more writers).  poll with timeout 0 is
		 * non-blocking.  */
		pfd.fd     = shadows[i].fd;
		pfd.events = 0; /* interested in POLLHUP only */
		pfd.revents = 0;

		if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLHUP)) {
			release_shadow(i);
			continue;
		}

		/* The pipe is full: a writer is blocked on it, or is
		 * about to be.  Nothing will ever drain this shadow, so
		 * keeping it would hang that writer — and whoever waits
		 * on it — where without proot the write would simply
		 * fail with EPIPE.  */
		if (writer_would_block(shadows[i].fd)) {
			release_shadow(i);
			continue;
		}

		/* Backstop: the race is long over, and slots are few.  */
		if (elapsed_ms(&shadows[i].birth) >= SHADOW_MAX_AGE_MS)
			release_shadow(i);
	}
}

bool shadow_pipes_held(void)
{
	return shadows_held > 0;
}

void shadow_pipes_set_timer(bool enabled)
{
	static bool armed = false;
	struct itimerval timer;

	if (!enabled && !armed)
		return;

	bzero(&timer, sizeof(timer));
	if (enabled)
		timer.it_value.tv_usec = SHADOW_TIMER_MS * 1000;

	if (setitimer(ITIMER_REAL, &timer, NULL) < 0)
		return;

	armed = enabled;
}
