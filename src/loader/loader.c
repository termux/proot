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

#include <stdbool.h>     /* bool, true, false,  */

#define NO_LIBC_HEADER
#include "loader/script.h"
#include "compat.h"
#include "arch.h"

#if defined(ARCH_X86_64)
#    include "loader/assembly-x86_64.h"
#elif defined(ARCH_ARM_EABI)
#    include "loader/assembly-arm.h"
#elif defined(ARCH_X86)
#    include "loader/assembly-x86.h"
#elif defined(ARCH_ARM64)
#    include "loader/assembly-arm64.h"
#else
#    error "Unsupported architecture"
#endif

#if !defined(MMAP_OFFSET_SHIFT)
#    define MMAP_OFFSET_SHIFT 0
#endif

#define FATAL() do {				\
		SYSCALL(EXIT, 1, 182);		\
		__builtin_unreachable();	\
	} while (0)

#define unlikely(expr) __builtin_expect(!!(expr), 0)

/**
 * Clear the memory from @start (inclusive) to @end (exclusive).
 */
static inline void clear(word_t start, word_t end)
{
	byte_t *start_misaligned;
	byte_t *end_misaligned;

	word_t *start_aligned;
	word_t *end_aligned;

	/* Compute the number of mis-aligned bytes.  */
	word_t start_bytes = start % sizeof(word_t);
	word_t end_bytes   = end % sizeof(word_t);

	/* Compute aligned addresses.  */
	start_aligned = (word_t *) (start_bytes ? start + sizeof(word_t) - start_bytes : start);
	end_aligned   = (word_t *) (end - end_bytes);

	/* Clear leading mis-aligned bytes.  */
	start_misaligned = (byte_t *) start;
	while (start_misaligned < (byte_t *) start_aligned)
		*start_misaligned++ = 0;

	/* Clear aligned bytes.  */
	while (start_aligned < end_aligned)
		*start_aligned++ = 0;

	/* Clear trailing mis-aligned bytes.  */
	end_misaligned = (byte_t *) end_aligned;
	while (end_misaligned < (byte_t *) end)
		*end_misaligned++ = 0;
}

/**
 * Return the address of the last path component of @string_.  Note
 * that @string_ is not modified.
 */
static inline word_t basename(word_t string_)
{
	byte_t *string = (byte_t *) string_;
	byte_t *cursor;

	for (cursor = string; *cursor != 0; cursor++)
		;

	for (; *cursor != (byte_t) '/' && cursor > string; cursor--)
		;

	if (cursor != string)
		cursor++;

	return (word_t) cursor;
}

/**
 * Interpret the load script pointed to by @cursor.
 */
void _start(void *cursor)
{
	bool traced = false;
	bool reset_at_base = true;
	word_t at_base = 0;
	/* PIE relocation: the first segment of each PIE binary is mapped with
	 * addr=0 to let the kernel choose a conflict-free base.  pic_delta is
	 * the difference between the kernel-chosen base and the original
	 * planned address; it is applied to all subsequent segments and to
	 * entry_point / auxv values at startup. */
	word_t pic_delta = 0;
	word_t exec_pic_delta = 0;
	bool has_interp = false;

	word_t fd = -1;
	word_t status;

	while(1) {
		LoadStatement *stmt = cursor;

		switch (stmt->action) {
		case LOAD_ACTION_OPEN_NEXT:
			exec_pic_delta = pic_delta;
			pic_delta = 0;
			has_interp = true;
			status = SYSCALL(CLOSE, 1, fd);
			if (unlikely((int) status < 0))
				FATAL();
			/* Fall through.  */

		case LOAD_ACTION_OPEN:
#if defined(OPEN)
			fd = SYSCALL(OPEN, 3, stmt->open.string_address, O_RDONLY, 0);
#else
			fd = SYSCALL(OPENAT, 4, AT_FDCWD, stmt->open.string_address, O_RDONLY, 0);
#endif
			if (unlikely((int) fd < 0))
				FATAL();

			reset_at_base = true;

			cursor += LOAD_STATEMENT_SIZE(*stmt, open);
			break;

		case LOAD_ACTION_MMAP_FILE:
			status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
					stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED, fd,
					stmt->mmap.offset >> MMAP_OFFSET_SHIFT);
			if (unlikely(status != stmt->mmap.addr))
				FATAL();

			if (stmt->mmap.clear_length != 0)
				clear(stmt->mmap.addr + stmt->mmap.length - stmt->mmap.clear_length,
					stmt->mmap.addr + stmt->mmap.length);

			if (reset_at_base) {
				at_base = stmt->mmap.addr;
				reset_at_base = false;
			}

			cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
			break;

		case LOAD_ACTION_MMAP_PIC_FILE:
			if (reset_at_base) {
				/* First segment of a PIE binary: let the kernel
				 * choose a conflict-free base address. */
				status = SYSCALL(MMAP, 6, 0, stmt->mmap.length,
						stmt->mmap.prot, MAP_PRIVATE, fd,
						stmt->mmap.offset >> MMAP_OFFSET_SHIFT);
				/* Use IS_ERR_VALUE-style check: on 32-bit targets,
				 * valid high addresses (e.g. 0xb7...) look negative
				 * when cast to long; mmap errors are in [-4095,-1]. */
				if (unlikely(status >= (word_t)-4095))
					FATAL();
				pic_delta = status - stmt->mmap.addr;
				at_base = status;
				reset_at_base = false;
			} else {
				/* Subsequent segments: MAP_FIXED at delta-adjusted
				 * address within the kernel-assigned region. */
				word_t adjusted = stmt->mmap.addr + pic_delta;
				status = SYSCALL(MMAP, 6, adjusted, stmt->mmap.length,
						stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED, fd,
						stmt->mmap.offset >> MMAP_OFFSET_SHIFT);
				if (unlikely(status != adjusted))
					FATAL();
			}

			if (stmt->mmap.clear_length != 0) {
				word_t actual = stmt->mmap.addr + pic_delta;
				clear(actual + stmt->mmap.length - stmt->mmap.clear_length,
					actual + stmt->mmap.length);
			}

			cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
			break;

		case LOAD_ACTION_MMAP_ANON:
			status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
					stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			if (unlikely(status != stmt->mmap.addr))
				FATAL();

			cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
			break;

		case LOAD_ACTION_MMAP_PIC_ANON:
			if (reset_at_base) {
				/* First segment (anon) of a PIE binary: let the
				 * kernel choose the base address. */
				status = SYSCALL(MMAP, 6, 0, stmt->mmap.length,
						stmt->mmap.prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				/* IS_ERR_VALUE-style: see LOAD_ACTION_MMAP_PIC_FILE. */
				if (unlikely(status >= (word_t)-4095))
					FATAL();
				pic_delta = status - stmt->mmap.addr;
				at_base = status;
				reset_at_base = false;
			} else {
				word_t adjusted = stmt->mmap.addr + pic_delta;
				status = SYSCALL(MMAP, 6, adjusted, stmt->mmap.length,
						stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
				if (unlikely(status != adjusted))
					FATAL();
			}

			cursor += LOAD_STATEMENT_SIZE(*stmt, mmap);
			break;

		case LOAD_ACTION_MAKE_STACK_EXEC:
			SYSCALL(MPROTECT, 3,
				stmt->make_stack_exec.start, 1,
				PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN);

			cursor += LOAD_STATEMENT_SIZE(*stmt, make_stack_exec);
			break;

		case LOAD_ACTION_START_TRACED:
			traced = true;
			/* Fall through.  */

		case LOAD_ACTION_START: {
			word_t *cursor2 = (word_t *) stmt->start.stack_pointer;
			const word_t argc = cursor2[0];
			const word_t at_execfn = cursor2[1];
			/* Apply PIE relocation deltas computed at mmap time.
			 * entry_point comes from the interp (if present) or exec,
			 * so it uses the current pic_delta.  at_phdr and at_entry
			 * always reference the executable, so they use its delta. */
			const word_t eff_exec_delta = has_interp ? exec_pic_delta : pic_delta;
			const word_t actual_entry = stmt->start.entry_point + pic_delta;
			const word_t actual_at_phdr = stmt->start.at_phdr + eff_exec_delta;
			const word_t actual_at_entry = stmt->start.at_entry + eff_exec_delta;
			word_t name;

			status = SYSCALL(CLOSE, 1, fd);
			if (unlikely((int) status < 0))
				FATAL();

			/* Right after execve, the stack content is as follow:
			 *
			 *   +------+--------+--------+--------+
			 *   | argc | argv[] | envp[] | auxv[] |
			 *   +------+--------+--------+--------+
			 */

			/* Skip argv[].  */
			cursor2 += argc + 1;

			/* Skip envp[].  */
			do cursor2++; while (cursor2[0] != 0);
			cursor2++;

			/* Adjust auxv[].  */
			do {
				switch (cursor2[0]) {
				case AT_PHDR:
					cursor2[1] = actual_at_phdr;
					break;

				case AT_PHENT:
					cursor2[1] = stmt->start.at_phent;
					break;

				case AT_PHNUM:
					cursor2[1] = stmt->start.at_phnum;
					break;

				case AT_ENTRY:
					cursor2[1] = actual_at_entry;
					break;

				case AT_BASE:
					cursor2[1] = at_base;
					break;

				case AT_EXECFN:
					/* stmt->start.at_execfn can't be used for now since it is
					 * currently stored in a location that will be scratched
					 * by the process (below the final stack pointer).  */
					cursor2[1] = at_execfn;
					break;

				default:
					break;
				}
				cursor2 += 2;
			} while (cursor2[0] != AT_NULL);

			/* Note that only 2 arguments are actually necessary... */
			name = basename(stmt->start.at_execfn);
			SYSCALL(PRCTL, 3, PR_SET_NAME, name, 0);

			if (unlikely(traced))
				SYSCALL(EXECVE, 6, 1,
					stmt->start.stack_pointer,
					actual_entry, 2, 3, 4);
			else
				BRANCH(stmt->start.stack_pointer, actual_entry);
			FATAL();
		}

		default:
			FATAL();
		}
	}

	FATAL();
}
