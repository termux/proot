#ifndef FAKE_ID0_SOCKET_H
#define FAKE_ID0_SOCKET_H

#include <stdbool.h>

#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "extension/fake_id0/config.h"
#include "arch.h"

bool get_socket_syscall_args(const Tracee *tracee, Sysnum sysnum, word_t call,
			     word_t *args, size_t nb_args);
bool is_audit_socket(const Tracee *tracee);
int handle_socket_exit_end(Tracee *tracee, Config *config);

#endif /* FAKE_ID0_SOCKET_H */
