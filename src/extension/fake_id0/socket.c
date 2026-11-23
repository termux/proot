#include <assert.h>      /* assert(3), */
#include <errno.h>       /* E*, */
#include <sys/socket.h>  /* AF_NETLINK, */
#include <linux/net.h>   /* SYS_SOCKET, */
#include <linux/netlink.h> /* NETLINK_AUDIT, */

#include "tracee/reg.h"
#include "syscall/socket.h"
#include "extension/fake_id0/socket.h"

/**
 * Put in @args the @nb_args first arguments of the current syscall of
 * @tracee, as it made it, when this is the socket syscall @sysnum or
 * the socketcall(2) that stands for it, @call -- the way 32-bit x86
 * programs make socket syscalls.  This function returns false if
 * @tracee made another syscall or if the arguments of socketcall(2)
 * can't be read, otherwise true.
 */
bool get_socket_syscall_args(const Tracee *tracee, Sysnum sysnum, word_t call,
			     word_t *args, size_t nb_args)
{
	Sysnum current = get_sysnum(tracee, ORIGINAL);
	size_t i;

	assert(nb_args <= 6);

	if (current == sysnum) {
		for (i = 0; i < nb_args; i++)
			args[i] = peek_reg(tracee, ORIGINAL, SYSARG_1 + i);
		return true;
	}

	if (current == PR_socketcall && peek_reg(tracee, ORIGINAL, SYSARG_1) == call)
		return peek_socketcall_args(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2),
					    args, nb_args) == 0;

	return false;
}

/**
 * Tell whether the current syscall of @tracee creates a netlink audit
 * socket.
 */
bool is_audit_socket(const Tracee *tracee)
{
	word_t args[3];

	return (get_socket_syscall_args(tracee, PR_socket, SYS_SOCKET, args, 3)
		&& args[0] == AF_NETLINK
		&& args[2] == NETLINK_AUDIT);
}

int handle_socket_exit_end(Tracee *tracee, Config *config) {
	word_t result;

	/* Override only permission errors.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result != -EPERM && (int) result != -EACCES)
		return 0;

	/* Emulate audit functionality not compiled into kernel
	 * if tracee was supposed to have the capability.  */
	if (is_audit_socket(tracee) && config->euid == 0) /* TODO: || HAS_CAP(...) */
		return -EPROTONOSUPPORT;

	return 0;
}
