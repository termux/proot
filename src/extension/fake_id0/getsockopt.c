#include <sys/socket.h>  /* SOL_SOCKET,SO_PEERCRED */
#include <unistd.h>      /* getuid(2) */
#include <linux/net.h>   /* SYS_GETSOCKOPT, */

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "extension/extension.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/getsockopt.h"
#include "extension/fake_id0/socket.h"

/**
 * Get fake_id0 Config for given pid
 *
 * If pid isn't under fake_id0 returns NULL
 */
static Config *get_fake_id_for_pid(pid_t pid)
{
	Tracee *tracee = get_tracee(NULL, pid, false);
	if (tracee == NULL)
		return NULL;
	Extension *extension = get_extension(tracee, fake_id0_callback);
	if (extension == NULL)
		return NULL;
	return talloc_get_type_abort(extension->config, Config);
}

/**
 * Tell whether the current syscall of @tracee is getsockopt(2), made
 * directly or through socketcall(2), that asks for the credentials of
 * the peer of a socket.  If so, the address where they are reported is
 * put in @optval, unless it is NULL.
 */
bool is_peercred_getsockopt(const Tracee *tracee, word_t *optval)
{
	/* sockfd, level, optname, optval.  */
	word_t args[4];

	if (!get_socket_syscall_args(tracee, PR_getsockopt, SYS_GETSOCKOPT, args, 4))
		return false;

	if (args[1] != SOL_SOCKET || args[2] != SO_PEERCRED)
		return false;

	if (optval != NULL)
		*optval = args[3];

	return true;
}

int handle_getsockopt_exit_end(Tracee *tracee) {
	word_t cred_addr;

	if (peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
	    && is_peercred_getsockopt(tracee, &cred_addr)) {
		struct ucred cred;
		int status = read_data(tracee, &cred, cred_addr, sizeof(struct ucred));
		if (status) return 0;
		Config *peer_config = get_fake_id_for_pid(cred.pid);
		/* A peer under another PRoot instance (or none) that runs
		 * as our real uid is the same user: report it with this
		 * tracee's own fake ids, as the tracee's getuid() does.  */
		if (peer_config == NULL && cred.uid == getuid())
			peer_config = get_fake_id_for_pid(tracee->pid);
		if (peer_config == NULL) return 0;
		cred.uid = peer_config->euid;
		cred.gid = peer_config->egid;
		write_data(tracee, cred_addr, &cred, sizeof(struct ucred));
	}
	return 0;
}
