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

#include <linux/auxvec.h>  /* AT_*,  */
#include <assert.h>        /* assert(3),  */
#include <errno.h>         /* E*,  */
#include <unistd.h>        /* write(3), close(3), */
#include <sys/types.h>     /* open(2), */
#include <sys/stat.h>      /* open(2), */
#include <fcntl.h>         /* open(2), */
#include <stdint.h>        /* uint*_t, */
#include <string.h>        /* memcpy(3), */
#include <sys/uio.h>       /* process_vm_readv(2), struct iovec, */

#include "execve/auxv.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "arch.h"
#include "build.h"         /* HAVE_PROCESS_VM, */


/**
 * Add the given vector [@type, @value] to @vectors.  This function
 * returns -errno if an error occurred, otherwise 0.
 */
int add_elf_aux_vector(ElfAuxVector **vectors, word_t type, word_t value)
{
	ElfAuxVector *tmp;
	size_t nb_vectors;

	assert(*vectors != NULL);

	nb_vectors = talloc_array_length(*vectors);

	/* Sanity checks.  */
	assert(nb_vectors > 0);
	assert((*vectors)[nb_vectors - 1].type == AT_NULL);

	tmp = talloc_realloc(talloc_parent(*vectors), *vectors, ElfAuxVector, nb_vectors + 1);
	if (tmp == NULL)
		return -ENOMEM;
	*vectors = tmp;

	/* Replace the sentinel with the new vector.  */
	(*vectors)[nb_vectors - 1].type  = type;
	(*vectors)[nb_vectors - 1].value = value;

	/* Restore the sentinel.  */
	(*vectors)[nb_vectors].type  = AT_NULL;
	(*vectors)[nb_vectors].value = 0;

	return 0;
}

/* The words of the initial stack -- argc, argv[], envp[], auxv[] --
 * are loaded by chunks, which spares a process_vm_readv(2) per word.
 * A chunk never spans a CHUNK_SIZE boundary, hence never two pages:
 * the stack ends with the strings these arrays point to, a read that
 * went beyond its last page would fail.  */
#define CHUNK_SIZE 1024

typedef struct {
	const Tracee *tracee;
	word_t address; /* Address of the loaded chunk in the tracee.  */
	size_t size;    /* Size of the loaded chunk, 0 if none.  */
	uint8_t data[CHUNK_SIZE];
} WordCache;

/**
 * Load in @cache the chunk of the memory of @cache->tracee that starts
 * at the given @address.  This function returns -1 if it couldn't be
 * loaded at once, otherwise 0.
 */
static int load_chunk(WordCache *cache, word_t address)
{
#if defined(HAVE_PROCESS_VM)
	size_t size = CHUNK_SIZE - address % CHUNK_SIZE;
	struct iovec local;
	struct iovec remote;
	ssize_t status;

	local.iov_base = cache->data;
	local.iov_len  = size;

	remote.iov_base = (void *) address;
	remote.iov_len  = size;

	status = process_vm_readv(cache->tracee->pid, &local, 1, &remote, 1, 0);
	if (status == (ssize_t) size) {
		cache->address = address;
		cache->size    = size;
		return 0;
	}
#else
	(void) address;
#endif

	cache->size = 0;
	return -1;
}

/**
 * Put in @value the word at the given @address in the memory of
 * @cache->tracee, loading the chunk it lies in unless @cache already
 * holds it.  This function returns -errno if an error occurred,
 * otherwise 0.
 */
static int read_word(WordCache *cache, word_t address, word_t *value)
{
	const size_t word_size = sizeof_word(cache->tracee);
	size_t offset;

	if (   cache->size == 0
	    || address < cache->address
	    || address - cache->address > cache->size - word_size) {
		/* Read this word alone when its chunk can't be loaded,
		 * as before chunks were used: process_vm_readv(2) may
		 * be missing, or a misaligned word may span a chunk
		 * boundary.  This fails silently, the callers report
		 * nothing either.  */
		if (load_chunk(cache, address) < 0 || cache->size < word_size) {
			cache->size = 0;
			errno = 0;
			*value = peek_word(cache->tracee, address);
			return (errno != 0 ? -errno : 0);
		}
	}

	offset = address - cache->address;
	if (word_size == sizeof(uint32_t)) {
		uint32_t value32;

		memcpy(&value32, &cache->data[offset], sizeof(value32));
		*value = value32;
	}
	else
		memcpy(value, &cache->data[offset], sizeof(*value));

	return 0;
}

/**
 * Get the address of the the ELF auxiliary vectors table for the
 * given @tracee.  This function returns 0 if an error occurred.
 */
word_t get_elf_aux_vectors_address(const Tracee *tracee)
{
	WordCache cache;
	word_t address;
	word_t data;
	int status;

	/* Sanity check: this works only in execve sysexit.  */
	assert(IS_IN_SYSEXIT2(tracee, PR_execve));

	cache.tracee = tracee;
	cache.size   = 0;

	/* Right after execve, the stack layout is:
	 *
	 *     argc, argv[0], ..., 0, envp[0], ..., 0, auxv[0].type, auxv[0].value, ..., 0, 0
	 */
	address = peek_reg(tracee, CURRENT, STACK_POINTER);

	/* Read: argc */
	status = read_word(&cache, address, &data);
	if (status < 0)
		return 0;

	/* Skip: argc, argv, 0 */
	address += (1 + data + 1) * sizeof_word(tracee);

	/* Skip: envp, 0 */
	do {
		status = read_word(&cache, address, &data);
		if (status < 0)
			return 0;
		address += sizeof_word(tracee);
	} while (data != 0);

	return address;
}

/**
 * Fetch ELF auxiliary vectors stored at the given @address in
 * @tracee's memory.  This function returns NULL if an error occurred,
 * otherwise it returns a pointer to the new vectors, in an ABI
 * independent form (the Talloc parent of this pointer is
 * @tracee->ctx).
 */
ElfAuxVector *fetch_elf_aux_vectors(const Tracee *tracee, word_t address)
{
	ElfAuxVector *vectors = NULL;
	ElfAuxVector vector;
	WordCache cache;
	int status;

	cache.tracee = tracee;
	cache.size   = 0;

	/* It is assumed the sentinel always exists.  */
	vectors = talloc_array(tracee->ctx, ElfAuxVector, 1);
	if (vectors == NULL)
		return NULL;
	vectors[0].type  = AT_NULL;
	vectors[0].value = 0;

	while (1) {
		status = read_word(&cache, address, &vector.type);
		if (status < 0)
			return NULL;
		address += sizeof_word(tracee);

		if (vector.type == AT_NULL)
			break; /* Already added.  */

		status = read_word(&cache, address, &vector.value);
		if (status < 0)
			return NULL;
		address += sizeof_word(tracee);

		status = add_elf_aux_vector(&vectors, vector.type, vector.value);
		if (status < 0)
			return NULL;
	}

	return vectors;
}

/**
 * Store @value as the @index-th word of @data, an array of words of
 * the @tracee's ABI.
 */
static void store_word(const Tracee *tracee, uint8_t *data, size_t index, word_t value)
{
	const size_t word_size = sizeof_word(tracee);

	if (word_size == sizeof(uint32_t)) {
		uint32_t value32 = value;

		memcpy(&data[index * word_size], &value32, sizeof(value32));
	}
	else
		memcpy(&data[index * word_size], &value, sizeof(value));
}

/**
 * Push ELF auxiliary @vectors to the given @address in @tracee's
 * memory, all at once.  This function returns -errno if an error
 * occurred, otherwise 0.
 */
int push_elf_aux_vectors(Tracee *tracee, ElfAuxVector *vectors, word_t address)
{
	const size_t word_size = sizeof_word(tracee);
	size_t nb_vectors;
	uint8_t *data;
	size_t i;

	/* Count the vectors, including the sentinel.  */
	for (nb_vectors = 1; vectors[nb_vectors - 1].type != AT_NULL; nb_vectors++)
		;

	data = talloc_size(tracee->ctx, 2 * nb_vectors * word_size);
	if (data == NULL)
		return -ENOMEM;

	for (i = 0; i < nb_vectors - 1; i++) {
		store_word(tracee, data, 2 * i, vectors[i].type);
		store_word(tracee, data, 2 * i + 1, vectors[i].value);
	}

	store_word(tracee, data, 2 * i, AT_NULL);
	store_word(tracee, data, 2 * i + 1, 0);

	return write_data(tracee, address, data, 2 * nb_vectors * word_size);
}
