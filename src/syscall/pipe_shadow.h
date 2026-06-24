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

/**
 * If @tracee_fd is a pipe read end in @tracee_pid's fd table, open a
 * shadow reference to it in proot's own process space.  Must be called
 * at sysenter of close(), before the fd is released.
 *
 * The shadow keeps the pipe alive for child writers after the parent
 * closes its copy of the read end early (ptrace serialisation makes
 * this happen routinely, causing EPIPE in process substitution).
 * The shadow is never read — data remains in the pipe buffer for any
 * legitimate reader (diff, cat, …).
 */
void shadow_pipe_read_end(pid_t tracee_pid, int tracee_fd);

/**
 * Close any shadow fds whose pipe has no more writers (poll POLLHUP).
 * Call this once per event loop iteration; it is non-blocking.
 */
void shadow_pipes_close_eof(void);

#endif /* PIPE_SHADOW_H */
