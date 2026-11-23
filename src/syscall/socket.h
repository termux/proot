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

#ifndef SOCKET_H
#define SOCKET_H

#include "arch.h" /* word_t */
#include "tracee/tracee.h"

int translate_socketcall_enter(Tracee *tracee, word_t *sock_addr, int size, bool is_bind);
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size);
int finish_socket_bind(Tracee *tracee, int result);
bool prepare_recvfrom_exit(Tracee *tracee, int fd, word_t address, word_t size_address);
bool prepare_recvmsg_exit(Tracee *tracee, int fd, word_t msghdr_address);
bool prepare_recvmmsg_exit(Tracee *tracee, int fd, word_t vector_address, word_t vlen);
void translate_recvfrom_exit(Tracee *tracee, word_t address, word_t size_address, int result);
void translate_recvmsg_exit(Tracee *tracee, word_t msghdr_address, int result);
void translate_recvmmsg_exit(Tracee *tracee, word_t vector_address, int result);
int translate_send_address(Tracee *tracee, word_t *sock_addr, int size);
int translate_sendmsg_enter(Tracee *tracee, word_t *msghdr_addr);
int translate_sendmmsg_enter(Tracee *tracee, word_t *vector_addr, word_t *vlen);
int translate_sendmmsg_exit(Tracee *tracee, word_t vector_addr, word_t copy_addr, word_t count);
int translate_socketcall_send_enter(Tracee *tracee, word_t call, word_t *args_addr);
int peek_socketcall_args(const Tracee *tracee, word_t args_addr, word_t *args, size_t nb_args);
int push_socketcall_args(Tracee *tracee, const word_t *args, size_t nb_args);

#endif /* SOCKET_H */
