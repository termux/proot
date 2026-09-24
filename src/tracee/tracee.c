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

#include <sched.h>      /* CLONE_*,  */
#include <sys/types.h>  /* pid_t, size_t, */
#include <stdio.h>      /* fopen(3), fgets(3), sscanf(3), */
#include <unistd.h>     /* getpid(2), */
#include <stdlib.h>     /* NULL, */
#include <assert.h>     /* assert(3), */
#include <string.h>     /* bzero(3), */
#include <stdbool.h>    /* bool, true, false, */
#include <sys/queue.h>  /* LIST_*,  */
#include <talloc.h>     /* talloc_*, */
#include <signal.h>     /* kill(2), SIGKILL, */
#include <sys/ptrace.h> /* ptrace(2), PTRACE_*, */
#include <errno.h>      /* E*, */
#include <inttypes.h>   /* PRI*, */

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "syscall/sysnum.h"
#include "tracee/event.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "cli/note.h"

#include "compat.h"

static Tracees tracees;


/**
 * Remove @zombie from its parent's list of zombies.  Note: this is a
 * talloc destructor.
 */
static int remove_zombie(Tracee *zombie)
{
	LIST_REMOVE(zombie, link);
	return 0;
}

/**
 * Perform some specific treatments against @pointer according to its
 * type, before it gets unlinked from @tracee_->life_context.
 */
static void clean_life_span_object(const void *pointer, int depth UNUSED,
				int max_depth UNUSED, int is_ref UNUSED, void *tracee_)
{
	Binding *binding;
	Tracee *tracee;

	tracee = talloc_get_type_abort(tracee_, Tracee);

	/* So far, only bindings need a special treatment.  */
	binding = talloc_get_type(pointer, Binding);
	if (binding != NULL)
		remove_binding_from_all_lists(tracee, binding);
}

/**
 * Remove @tracee from the list of tracees and update all of its
 * children & ptracees, and its ptracer.  Note: this is a talloc
 * destructor.
 */
static int remove_tracee(Tracee *tracee)
{
	Tracee *relative;
	Tracee *ptracer;
	int event;

	LIST_REMOVE(tracee, link);

	/* Clean objects that are linked to this tracee's life
	 * span.  */
	talloc_report_depth_cb(tracee->life_context, 0, 100, clean_life_span_object, tracee);

	/* This could be optimize by using a dedicated list of
	 * children and ptracees.  */
	LIST_FOREACH(relative, &tracees, link) {
		/* Its children are now orphan.  */
		if (relative->parent == tracee)
			relative->parent = NULL;

		/* Its tracees are now free.  */
		if (relative->as_ptracee.ptracer == tracee) {
			/* Release the pending event, if any.  */
			relative->as_ptracee.ptracer = NULL;

			if (relative->as_ptracee.event4.proot.pending) {
				event = handle_tracee_event(relative,
							relative->as_ptracee.event4.proot.value);
				(void) restart_tracee(relative, event);
			}
			else if (relative->as_ptracee.event4.ptracer.pending) {
				event = relative->as_ptracee.event4.proot.value;
				(void) restart_tracee(relative, event);
			}

			bzero(&relative->as_ptracee, sizeof(relative->as_ptracee));
		}
	}

	/* Nothing else to do if it's not a ptracee.  */
	ptracer = tracee->as_ptracee.ptracer;
	if (ptracer == NULL)
		return 0;

	/* Zombify this ptracee until its ptracer is notified about
	 * its death.  */
	event = tracee->as_ptracee.event4.ptracer.value;
	if (tracee->as_ptracee.event4.ptracer.pending
	    && (WIFEXITED(event) || WIFSIGNALED(event))) {
		Tracee *zombie;

		zombie = new_dummy_tracee(ptracer);
		if (zombie != NULL) {
			LIST_INSERT_HEAD(&PTRACER.zombies, zombie, link);
			talloc_set_destructor(zombie, remove_zombie);

			zombie->parent = tracee->parent;
			zombie->clone = tracee->clone;
			zombie->pid = tracee->pid;

			detach_from_ptracer(tracee);
			attach_to_ptracer(zombie, ptracer);

			zombie->as_ptracee.event4.ptracer.pending = true;
			zombie->as_ptracee.event4.ptracer.value = event;
			zombie->as_ptracee.is_zombie = true;

			return 0;
		}
		/* Fallback to the common path.  */
	}

	detach_from_ptracer(tracee);

	/* Wake its ptracer if there's nothing else to wait for.  */
	if (PTRACER.nb_ptracees == 0 && PTRACER.wait_pid != 0) {
		/* Update the return value of ptracer's wait(2).  */
		poke_reg(ptracer, SYSARG_RESULT, -ECHILD);

		/* Don't forget to write its register cache back.  */
		(void) push_regs(ptracer);

		PTRACER.wait_pid = 0;
		(void) restart_tracee(ptracer, 0);
	}

	return 0;
}

/**
 * Allocate a new entry for a dummy tracee (no pid, no destructor, not
 * in the list of tracees, ...).  The new allocated memory is attached
 * to the given @context.  This function returns NULL if an error
 * occurred (ENOMEM), otherwise it returns the newly allocated
 * structure.
 */
Tracee *new_dummy_tracee(TALLOC_CTX *context)
{
	Tracee *tracee;

	tracee = talloc_zero(context, Tracee);
	if (tracee == NULL)
		return NULL;

	/* Allocate a memory collector.  */
	tracee->ctx = talloc_new(tracee);
	if (tracee->ctx == NULL)
		goto no_mem;

	/* By default new tracees have an empty file-system
	 * name-space and heap.  */
	tracee->fs = talloc_zero(tracee, FileSystemNameSpace);
	tracee->heap = talloc_zero(tracee, Heap);
	tracee->auxv_fd = -1;
	if (tracee->fs == NULL || tracee->heap == NULL)
		goto no_mem;

	return tracee;

no_mem:
	TALLOC_FREE(tracee);
	return NULL;
}

static uint64_t next_vpid = 1;

/**
 * Allocate a new entry for the tracee @pid, then set its destructor
 * and add it to the list of tracees.  This function returns NULL if
 * an error occurred (ENOMEM), otherwise it returns the newly
 * allocated structure.
 */
static Tracee *new_tracee(pid_t pid)
{
	Tracee *tracee;

	tracee = new_dummy_tracee(NULL);
	if (tracee == NULL)
		return NULL;

	talloc_set_destructor(tracee, remove_tracee);

	tracee->pid = pid;
	tracee->vpid = next_vpid++;

	LIST_INSERT_HEAD(&tracees, tracee, link);

	tracee->life_context = talloc_new(tracee);

	return tracee;
}

/**
 * Return the first [stopped?] tracee with the given
 * @pid (-1 for any) which has the given @ptracer, and which has a
 * pending event for its ptracer if @only_with_pevent is true.  See
 * wait(2) manual for the meaning of @wait_options.  This function
 * returns NULL if there's no such ptracee.
 */
static Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool only_stopped,
			bool only_with_pevent, word_t wait_options)
{
	Tracee *ptracee;

	/* Return zombies first.  */
	LIST_FOREACH(ptracee, &PTRACER.zombies, link) {
		/* Not the ptracee you're looking for?  */
		if (pid != ptracee->pid && pid != -1)
			continue;

		/* Not the expected kind of cloned process?  */
		if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
			continue;

		return ptracee;
	}

	LIST_FOREACH(ptracee, &tracees, link) {
		/* Discard tracees that don't have this ptracer.  */
		if (PTRACEE.ptracer != ptracer)
			continue;

		/* Not the ptracee you're looking for?  */
		if (pid != ptracee->pid && pid != -1)
			continue;

		/* Not the expected kind of cloned process?  */
		if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
			continue;

		/* No need to do more checks if its stopped state
		 * doesn't matter.  Be careful when using such
		 * maybe-running tracee.  */
		if (!only_stopped)
			return ptracee;

		/* Is this tracee in the stopped state?  */
		if (ptracee->running)
			continue;

		/* Has a pending event for its ptracer?  */
		if (PTRACEE.event4.ptracer.pending || !only_with_pevent)
			return ptracee;

		/* No need to go further if the specific tracee isn't
		 * in the expected state?  */
		if (pid == ptracee->pid)
			return NULL;
	}

	return NULL;
}

/**
 * Wrapper for get_ptracee(), this ensures only a stopped tracee is
 * returned (or NULL).
 */
Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
			bool only_with_pevent, word_t wait_options)
{
	return get_ptracee(ptracer, pid, true, only_with_pevent, wait_options);
}

/**
 * Wrapper for get_ptracee(), this ensures no running tracee is
 * returned.
 */
bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options)
{
	return (get_ptracee(ptracer, pid, false, false, wait_options) != NULL);
}

/**
 * Return the entry related to the tracee @pid.  If no entry were
 * found, a new one is created if @create is true, otherwise NULL is
 * returned.
 */
Tracee *get_tracee(const Tracee *current_tracee, pid_t pid, bool create)
{
	Tracee *tracee;

	/* Don't reset the memory collector if the searched tracee is
	 * the current one: there's likely pointers to the
	 * sub-allocated data in the caller.  */
	if (current_tracee != NULL && current_tracee->pid == pid)
		return (Tracee *)current_tracee;

	LIST_FOREACH(tracee, &tracees, link) {
		if (tracee->pid == pid) {
			/* Flush then allocate a new memory collector.  */
			TALLOC_FREE(tracee->ctx);
			tracee->ctx = talloc_new(tracee);

			return tracee;
		}
	}

	return (create ? new_tracee(pid) : NULL);
}

/**
 * Mark tracee as terminated and optionally take action.
 */
void terminate_tracee(Tracee *tracee)
{
	tracee->terminated = true;

	/* Case where the terminated tracee is marked
	   to kill all tracees on exit.
	*/
	if (tracee->killall_on_exit) {
		VERBOSE(tracee, 1, "terminating all tracees on exit");
		kill_all_tracees();
	}
}

/**
 * Free all tracees marked as terminated.
 */
void free_terminated_tracees()
{
	Tracee *next;

	/* Items can't be deleted when using LIST_FOREACH.  */
	next = tracees.lh_first;
	while (next != NULL) {
		Tracee *tracee = next;
		next = tracee->link.le_next;

		if (tracee->terminated)
			TALLOC_FREE(tracee);
	}
}

static int attach_child(Tracee *parent, word_t clone_flags, pid_t pid);

/**
 * Read the Tgid, PPid and TracerPid fields of /proc/@pid/status.  This
 * function returns -1 if they can't all be read, otherwise 0.
 */
static int read_proc_status_ids(pid_t pid, pid_t *tgid, pid_t *ppid, pid_t *tracer)
{
	char path[64];
	char line[128];
	int found = 0;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	file = fopen(path, "r");
	if (file == NULL)
		return -1;

	while (found != 7 && fgets(line, sizeof(line), file) != NULL) {
		if (sscanf(line, "Tgid: %d", tgid) == 1)
			found |= 1;
		else if (sscanf(line, "PPid: %d", ppid) == 1)
			found |= 2;
		else if (sscanf(line, "TracerPid: %d", tracer) == 1)
			found |= 4;
	}
	fclose(file);

	return (found == 7 ? 0 : -1);
}

/**
 * Return the stack pointer the child of the fork-like syscall @parent
 * is stopped in starts with: the stack the syscall was given, if any,
 * otherwise the stack of @parent itself.
 */
static word_t new_child_stack(Tracee *parent)
{
	word_t stack = 0;

	switch (get_sysnum(parent, CURRENT)) {
	case PR_clone:
		stack = peek_reg(parent, CURRENT, SYSARG_2);
		break;

	case PR_clone3: {
		/* The child starts at the top of the area described
		 * by the "stack" and "stack_size" fields of struct
		 * clone_args, the 6th and 7th 64-bit words.  */
		word_t args = peek_reg(parent, CURRENT, SYSARG_1);
		word_t size;

		errno = 0;
		stack = peek_word(parent, args + 5 * 8);
		size  = peek_word(parent, args + 6 * 8);
		stack = (errno != 0 || stack == 0 ? 0 : stack + size);
		break;
	}

	default:
		break;
	}

	return (stack != 0 ? stack : peek_reg(parent, CURRENT, STACK_POINTER));
}

/**
 * Tell whether @child, stopped but unknown to PRoot yet, was created
 * by the fork-like syscall whose event didn't name the child @parent
 * got (see new_child()).
 */
static bool is_pending_child_of(const Tracee *parent, Tracee *child)
{
	word_t flags = parent->pending_clone_flags;
	pid_t child_tgid, child_ppid, parent_tgid, parent_ppid, tracer;
	bool related;

	if (read_proc_status_ids(child->pid, &child_tgid, &child_ppid, &tracer) < 0
	    || read_proc_status_ids(parent->pid, &parent_tgid, &parent_ppid, &tracer) < 0)
		return false;

	/* A new thread joins the thread group of its creator; a new
	 * process is the child of the process which forked it, unless
	 * it was given the parent of that process.  */
	if ((flags & CLONE_THREAD) != 0)
		related = (child_tgid == parent_tgid);
	else if ((flags & CLONE_PARENT) != 0)
		related = (child_ppid == parent_ppid);
	else
		related = (child_ppid == parent_tgid);

	if (!related)
		return false;

	/* That still can't tell apart the threads of a process forking
	 * at the same time, but their children can: the stack a new
	 * child starts with, untouched until its first stop, is the one
	 * its parent asked for, and no two threads share a stack.  */
#if defined(ARCH_ARM64)
	child->is_aarch32 = parent->is_aarch32;
#endif
	if (fetch_regs(child) < 0)
		return false;

	return (peek_reg(child, CURRENT, STACK_POINTER) == parent->pending_child_sp);
}

/**
 * Register the stopped tracees PRoot doesn't know yet whose parent is
 * blocked in a vfork-like syscall that was reported without the new
 * child's PID (see new_child()).  Such a parent reaches the exit of
 * that syscall only once its child has run, so its child can't wait
 * for it.  Other parents are handled when their syscall exits, where
 * its result names the child exactly (see resolve_pending_child()).
 */
void adopt_held_children(void)
{
	bool vfork_pending = false;
	Tracee *parent;
	Tracee *child;

	LIST_FOREACH(parent, &tracees, link) {
		if (parent->pending_child && (parent->pending_clone_flags & CLONE_VFORK) != 0)
			vfork_pending = true;
	}

	if (!vfork_pending)
		return;

	LIST_FOREACH(child, &tracees, link) {
		if (child->exe != NULL || child->sigstop != SIGSTOP_PENDING || child->terminated)
			continue;

		LIST_FOREACH(parent, &tracees, link) {
			if (!parent->pending_child
			    || (parent->pending_clone_flags & CLONE_VFORK) == 0
			    || parent->exe == NULL
			    || parent->terminated
			    || !is_pending_child_of(parent, child))
				continue;

			parent->pending_child = false;
			(void) attach_child(parent, parent->pending_clone_flags, child->pid);
			break;
		}
	}
}

/**
 * Register the child @parent created with a fork-like syscall that was
 * reported without the new child's PID (see new_child()), now that
 * @parent is at the exit stage of a syscall.  If that syscall is the
 * one which forked, its result is the PID in question.
 */
void resolve_pending_child(Tracee *parent)
{
	pid_t tgid, ppid, tracer;
	Tracee *child;
	pid_t pid;

	switch (get_sysnum(parent, ORIGINAL)) {
	case PR_clone:
	case PR_clone3:
	case PR_fork:
	case PR_vfork:
		break;

	default:
		/* The result of any other syscall isn't a PID: never
		 * mistake it for the child's.  */
		return;
	}

	parent->pending_child = false;

	pid = (pid_t) (int) peek_reg(parent, CURRENT, SYSARG_RESULT);

	/* Already registered by adopt_held_children()?  */
	child = (pid > 0 ? get_tracee(parent, pid, false) : NULL);
	if (child != NULL && child->exe != NULL)
		return;

	/* Make sure that PID designates a process PRoot is tracing
	 * before tracking it (and killing it on exit).  */
	if (pid <= 0
	    || read_proc_status_ids(pid, &tgid, &ppid, &tracer) < 0
	    || tracer != getpid()) {
		note(parent, WARNING, INTERNAL,
			"vpid %" PRIu64 ": can't find the child of a fork reported without its pid",
			parent->vpid);
		parent->clone_stripped_newns = false;
		parent->clone_stripped_newnet = false;
		return;
	}

	(void) attach_child(parent, parent->pending_clone_flags, pid);
}

/**
 * Make new @parent's child inherit from it.  Depending on
 * @clone_flags, some information are copied or shared.  This function
 * returns -errno if an error occured, otherwise 0.
 */
int new_child(Tracee *parent, word_t clone_flags)
{
	unsigned long pid = 0;
	int status;

	/* If the tracee calls clone(2) with the CLONE_VFORK flag,
	 * PTRACE_EVENT_VFORK will be delivered instead [...];
	 * otherwise if the tracee calls clone(2) with the exit signal
	 * set to SIGCHLD, PTRACE_EVENT_FORK will be delivered [...]
	 *
	 * -- ptrace(2) man-page
	 *
	 * That means we have to check if it's actually a clone(2) in
	 * order to get the right flags.
	 */
	status = fetch_regs(parent);
	if (status >= 0 && get_sysnum(parent, CURRENT) == PR_clone)
		clone_flags = peek_reg(parent, CURRENT, SYSARG_1);
        else if (status >= 0 && get_sysnum(parent, CURRENT) == PR_clone3)
                // Look at the first word of the clone_args structure, which
                // contains the usual clone flags.
                clone_flags = peek_word(parent, peek_reg(parent, CURRENT, SYSARG_1));

	/* Get the pid of the parent's new child.  Some kernels (seen
	 * on aarch64 4.14.357 builds) clear the message of the last
	 * ptrace event on every ptrace request, so the PID reads as 0,
	 * although the fork succeeded and the child is already waiting
	 * for PRoot, stopped.  Register that child later: from the
	 * result of the syscall once @parent reaches its exit, or from
	 * the child's own stop when @parent can't get there before the
	 * child has run, ie. when blocked in vfork(2).  */
	status = ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &pid);
	if (status < 0 || pid == 0) {
		VERBOSE(parent, 1, "vpid %" PRIu64 ": fork event without the child's pid",
			parent->vpid);
		parent->pending_child = true;
		parent->pending_clone_flags = clone_flags;
		parent->pending_child_sp = new_child_stack(parent);
		adopt_held_children();
		return 0;
	}

	return attach_child(parent, clone_flags, (pid_t) pid);
}

/**
 * Register @pid as the new child of @parent, see new_child().
 */
static int attach_child(Tracee *parent, word_t clone_flags, pid_t pid)
{
	int ptrace_options;
	Tracee *child;

	child = get_tracee(parent, pid, true);
	if (child == NULL) {
		note(parent, WARNING, SYSTEM, "running out of memory");
		return -ENOMEM;
	}

	/* Sanity checks.  */
	assert(child != NULL
	    && child->exe == NULL
	    && child->fs->cwd == NULL
	    && child->fs->bindings.pending == NULL
	    && child->fs->bindings.guest == NULL
	    && child->fs->bindings.host == NULL
	    && child->qemu == NULL
	    && child->glue == NULL
	    && child->parent == NULL
	    && child->as_ptracee.ptracer == NULL);

	child->verbose = parent->verbose;
	child->seccomp = parent->seccomp;
	child->sysexit_pending = parent->sysexit_pending;
	child->execfn_addr = parent->execfn_addr;
	child->auxv_fd = parent->auxv_fd;
	child->no_new_privs = parent->no_new_privs;
	child->seen_execve = parent->seen_execve;
#ifdef HAS_POKEDATA_WORKAROUND
	child->pokedata_workaround_stub_addr = parent->pokedata_workaround_stub_addr;
#endif
#ifdef ARCH_ARM64
	child->is_aarch32 = parent->is_aarch32;
#endif

	/* If CLONE_VM is set, the calling process and the child
	 * process run in the same memory space [...] any memory
	 * mapping or unmapping performed with mmap(2) or munmap(2) by
	 * the child or calling process also affects the other
	 * process.
	 *
	 * If CLONE_VM is not set, the child process runs in a
	 * separate copy of the memory space of the calling process at
	 * the time of clone().  Memory writes or file
	 * mappings/unmappings performed by one of the processes do
	 * not affect the other, as with fork(2).
	 *
	 * -- clone(2) man-page
	 */
	TALLOC_FREE(child->heap);
	child->heap = ((clone_flags & CLONE_VM) != 0)
		? talloc_reference(child, parent->heap)
		: talloc_memdup(child, parent->heap, sizeof(Heap));
	if (child->heap == NULL)
		return -ENOMEM;

	child->load_info = talloc_reference(child, parent->load_info);

	/* If CLONE_PARENT is set, then the parent of the new child
	 * (as returned by getppid(2)) will be the same as that of the
	 * calling process.
	 *
	 * If CLONE_PARENT is not set, then (as with fork(2)) the
	 * child's parent is the calling process.
	 *
	 * -- clone(2) man-page
	 */
	if ((clone_flags & CLONE_PARENT) != 0)
		child->parent = parent->parent;
	else
		child->parent = parent;

	/* Remember if this child belongs to the same thread group as
	 * its parent.  This is currently useful for ptrace emulation
	 * only but it deserves to be extended to support execve(2)
	 * specificity (ie. when a thread calls execve(2), its pid
	 * gets replaced by the pid of its thread group leader).  */
	child->clone = ((clone_flags & CLONE_THREAD) != 0);

	/* Depending on how the new process is created, it may be
	 * automatically traced by the parent's tracer.  */
	ptrace_options = ( clone_flags == 0			? PTRACE_O_TRACEFORK
			: (clone_flags & 0xFF) == SIGCHLD	? PTRACE_O_TRACEFORK
			: (clone_flags & CLONE_VFORK) != 0	? PTRACE_O_TRACEVFORK
			: 					  PTRACE_O_TRACECLONE);
	if (parent->as_ptracee.ptracer != NULL
	    && (   (ptrace_options & parent->as_ptracee.options) != 0
		|| (clone_flags & CLONE_PTRACE) != 0)) {
		attach_to_ptracer(child, parent->as_ptracee.ptracer);

		/* All these flags are inheritable, no matter why this
		 * child is being traced.  */
		child->as_ptracee.options |= (parent->as_ptracee.options
					      & ( PTRACE_O_TRACECLONE
						| PTRACE_O_TRACEEXEC
						| PTRACE_O_TRACEEXIT
						| PTRACE_O_TRACEFORK
						| PTRACE_O_TRACESYSGOOD
						| PTRACE_O_TRACEVFORK
						| PTRACE_O_TRACEVFORKDONE));
	}

	/* If CLONE_FS is set, the parent and the child process share
	 * the same file system information.  This includes the root
	 * of the file system, the current working directory, and the
	 * umask.  Any call to chroot(2), chdir(2), or umask(2)
	 * performed by the parent process or the child process also
	 * affects the other process.
	 *
	 * If CLONE_FS is not set, the child process works on a copy
	 * of the file system information of the parent process at the
	 * time of the clone() call.  Calls to chroot(2), chdir(2),
	 * umask(2) performed later by one of the processes do not
	 * affect the other process.
	 *
	 * -- clone(2) man-page
	 */
	TALLOC_FREE(child->fs);
	if ((clone_flags & CLONE_FS) != 0) {
		/* File-system name-space is shared.  */
		child->fs = talloc_reference(child, parent->fs);
	}
	else {
		/* File-system name-space is copied.  */
		child->fs = talloc_zero(child, FileSystemNameSpace);
		if (child->fs == NULL)
			return -ENOMEM;

		child->fs->cwd = talloc_strdup(child->fs, parent->fs->cwd);
		if (child->fs->cwd == NULL)
			return -ENOMEM;
		talloc_set_name_const(child->fs->cwd, "$cwd");

		if (parent->clone_stripped_newns
		    && parent->fs->bindings.guest != NULL) {
			/* Caller asked for CLONE_NEWNS (which we
			 * silently stripped).  Give the child its own
			 * copy of the binding tree so emulated mount(2)
			 * calls don't propagate back to the parent.  */
			Binding *iter;

			child->fs->bindings.guest = talloc_zero(child->fs, Bindings);
			child->fs->bindings.host  = talloc_zero(child->fs, Bindings);
			if (   child->fs->bindings.guest == NULL
			    || child->fs->bindings.host  == NULL)
				return -ENOMEM;
			CIRCLEQ_INIT(child->fs->bindings.guest);
			CIRCLEQ_INIT(child->fs->bindings.host);

			for (iter = CIRCLEQ_FIRST(parent->fs->bindings.guest);
			     iter != (void *) parent->fs->bindings.guest;
			     iter = CIRCLEQ_NEXT(iter, link.guest))
				(void) insort_binding3(child, child->fs,
						       iter->host.path,
						       iter->guest.path);
		}
		else {
			/* Bindings are shared across file-system name-spaces since a
			 * "mount --bind" made by a process affects all other processes
			 * under Linux.  Actually they are copied when a sub
			 * reconfiguration occured (nested proot or chroot(2)).  */
			child->fs->bindings.guest = talloc_reference(child->fs, parent->fs->bindings.guest);
			child->fs->bindings.host  = talloc_reference(child->fs, parent->fs->bindings.host);
		}
	}

	/* Always consume the stripped-NEWNS flag once a child has been
	 * processed, regardless of which branch above we took (the flag
	 * could persist otherwise — e.g. when CLONE_FS sent us straight
	 * to the shared-fs path, or when bindings.guest wasn't ready
	 * yet — and incorrectly isolate the bindings of an unrelated
	 * later clone in the same parent).  */
	parent->clone_stripped_newns = false;

	/* A child either enters the network namespace its parent asked
	 * for with this very clone(2), or stays in the one the parent
	 * already believes it lives in.  Either way it gets rtnetlink
	 * answers for a namespace of its own (see enter.c).  */
	child->fake_netns = parent->fake_netns || parent->clone_stripped_newnet;
	parent->clone_stripped_newnet = false;

	/* Open fds survive fork(2)/clone(2), so the child has to keep
	 * recognising the netlink sockets its parent opened.  The reply
	 * pending on either of them doesn't carry over: it belongs to
	 * whoever sent the request.  */
	for (int i = 0; i < parent->fake_netlink_fds_count; i++) {
		child->fake_netlink_fds[i].fd = parent->fake_netlink_fds[i].fd;
		child->fake_netlink_fds[i].reply = NULL;
		child->fake_netlink_fds[i].reply_len = 0;
		child->fake_netlink_fds[i].reply_off = 0;
	}
	child->fake_netlink_fds_count = parent->fake_netlink_fds_count;
	memcpy(child->netlink_route_fds, parent->netlink_route_fds,
	       sizeof(child->netlink_route_fds));
	child->netlink_route_fds_count = parent->netlink_route_fds_count;

	/* The path to the executable is unshared only once the child
	 * process does a call to execve(2).  */
	child->exe = talloc_reference(child, parent->exe);

	child->qemu = talloc_reference(child, parent->qemu);
	child->glue = talloc_reference(child, parent->glue);

	child->host_ldso_paths  = talloc_reference(child, parent->host_ldso_paths);
	child->guest_ldso_paths = talloc_reference(child, parent->guest_ldso_paths);

	child->tool_name = parent->tool_name;

	inherit_extensions(child, parent, clone_flags);

	/* Restart the child tracee if it was already alive but
	 * stopped until that moment.  */
	if (child->sigstop == SIGSTOP_PENDING) {
		bool keep_stopped = false;

		child->sigstop = SIGSTOP_ALLOWED;

		/* Notify its ptracer if it is ready to be traced.  */
		if (child->as_ptracee.ptracer != NULL) {
			/* Sanity check.  */
			assert(!child->as_ptracee.tracing_started);

#ifndef __W_STOPCODE
	#define __W_STOPCODE(sig) ((sig) << 8 | 0x7f)
#endif
			keep_stopped = handle_ptracee_event(child, __W_STOPCODE(SIGSTOP));

			/* Note that this event was already handled by
			 * PRoot since child->as_ptracee.ptracer was
			 * NULL up to now.  */
			child->as_ptracee.event4.proot.pending = false;
			child->as_ptracee.event4.proot.value   = 0;
		}

		if (!keep_stopped)
			(void) restart_tracee(child, 0);
	}

	VERBOSE(child, 1, "vpid %" PRIu64 ": pid %d", child->vpid, child->pid);

	return 0;
}

/**
 * Helper for swap_config().
 */
static void reparent_config(Tracee *new_parent, Tracee *old_parent)
{
	new_parent->verbose = old_parent->verbose;

#define REPARENT(field) do {							\
		talloc_reparent(old_parent, new_parent, old_parent->field);	\
		new_parent->field = old_parent->field;				\
	} while(0);

	REPARENT(fs);
	REPARENT(exe);
	REPARENT(qemu);
	REPARENT(glue);
	REPARENT(extensions);

#undef REPARENT
}

/**
 * Swap configuration (pointers and parentality) between @tracee1 and @tracee2.
 */
int swap_config(Tracee *tracee1, Tracee *tracee2)
{
	Tracee *tmp;

	tmp = talloc_zero(tracee1->ctx, Tracee);
	if (tmp == NULL)
		return -ENOMEM;

	reparent_config(tmp,     tracee1);
	reparent_config(tracee1, tracee2);
	reparent_config(tracee2, tmp);

	return 0;
}

/* Send the KILL signal to all tracees.  */
void kill_all_tracees()
{
	Tracee *tracee;

	LIST_FOREACH(tracee, &tracees, link)
		kill(tracee->pid, SIGKILL);
}

Tracees *get_tracees_list_head() {
	return &tracees;
}
