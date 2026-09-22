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

#ifndef EXECVE_H
#define EXECVE_H

#include <linux/limits.h>    /* PATH_MAX, */
#include <stdbool.h>         /* bool, */

#include "tracee/tracee.h"
#include "execve/elf.h"
#include "arch.h"

extern int translate_execve_enter(Tracee *tracee);
extern void translate_execve_exit(Tracee *tracee);
extern int translate_and_check_exec(Tracee *tracee, char host_path[PATH_MAX], const char *user_path);

/**
 * State passed along with the EXECVE_PROC_EXE event.
 */
struct execve_proc_exe_state {
	/* Host path of the executable PRoot will load.  */
	const char *host_path;

	/* Guest path to report through "/proc/<PID>/exe".  An extension may
	 * overwrite it -- the buffer is PATH_MAX bytes long -- and set
	 * @substituted accordingly.  */
	char *guest_path;

	/* Whether @guest_path was replaced by an extension.  */
	bool substituted;
};

typedef struct mapping {
	word_t addr;
	word_t length;
	word_t clear_length;
	word_t prot;
	word_t flags;
	word_t fd;
	word_t offset;
} Mapping;

typedef struct load_info {
	char *host_path;
	char *user_path;
	char *raw_path;
	Mapping *mappings;
	ElfHeader elf_header;
	bool needs_executable_stack;

	struct load_info *interp;
} LoadInfo;

#define IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee) (			\
		(tracee)->as_ptracee.ptracer != NULL			\
		&& peek_reg((tracee), ORIGINAL, SYSARG_1) == (word_t) 1	\
		&& peek_reg((tracee), ORIGINAL, SYSARG_4) == (word_t) 2	\
		&& peek_reg((tracee), ORIGINAL, SYSARG_5) == (word_t) 3	\
		&& peek_reg((tracee), ORIGINAL, SYSARG_6) == (word_t) 4)

#endif /* EXECVE_H */
