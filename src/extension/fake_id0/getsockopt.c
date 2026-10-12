#include <sys/socket.h>  /* SOL_SOCKET,SO_PEERCRED */
#include <unistd.h>      /* getuid(2) */

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "extension/extension.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/getsockopt.h"

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

int handle_getsockopt_exit_end(Tracee *tracee) {
	if (
	    peek_reg(tracee, ORIGINAL, SYSARG_2) == SOL_SOCKET &&
	    peek_reg(tracee, ORIGINAL, SYSARG_3) == SO_PEERCRED &&
	    peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0) {

		struct ucred cred;
		word_t cred_addr = peek_reg(tracee, ORIGINAL, SYSARG_4);
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
