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

#ifndef PIPE_SHADOW_H
#define PIPE_SHADOW_H

#include <sys/types.h>
#include <stdbool.h>

/**
 * Open a shadow reference to @read_fd, the read end of the pipe
 * @tracee_pid has just created, in proot's own process space.  Must be
 * called at the exit stage of pipe(2) or pipe2(2).
 *
 * The shadow keeps the pipe alive for child writers after the parent
 * closes its copy of the read end early (ptrace serialisation makes
 * this happen routinely, causing EPIPE in process substitution).
 * The shadow is never read — data remains in the pipe buffer for any
 * legitimate reader (diff, cat, …).
 */
void shadow_new_pipe(pid_t tracee_pid, int read_fd);

/**
 * Close any shadow fd that has become useless — no writer is left
 * (POLLHUP), the pipe is too full for a writer to make progress, or
 * the race it was opened for is long over.  Call this once per
 * event loop iteration; it is non-blocking.
 */
void shadow_pipes_reap(void);

/**
 * Return true when at least one shadow fd is currently held.
 */
bool shadow_pipes_held(void);

/**
 * Arm (@enabled) or disarm a one-shot ITIMER_REAL used to interrupt
 * waitpid(2) so shadow_pipes_reap() runs even while every tracee is
 * blocked — a writer blocked on a full pipe generates no ptrace event.
 * The caller must handle SIGALRM without SA_RESTART.
 */
void shadow_pipes_set_timer(bool enabled);

#endif /* PIPE_SHADOW_H */
