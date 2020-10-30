#include "extension/sysvipc/sysvipc.h"
#include "tracee/seccomp.h"

#include <assert.h> /* assert */
#include <unistd.h> /* syscall */
#include <sys/syscall.h> /* __NR_tkill */
#include <errno.h> /* E* */


#include "sysvipc_internal.h"


static FilteredSysnum filtered_sysnums[] = {
	{ PR_msgget,		0 },
	{ PR_msgsnd,		0 },
	{ PR_msgrcv,		0 },
	{ PR_msgctl,		0 },
	{ PR_semget,		0 },
	{ PR_semop,		0 },
	{ PR_semtimedop,	0 },
	{ PR_semctl,		0 },
	FILTERED_SYSNUM_END,
};


static int sysvipc_syscall_common(Tracee *tracee, struct SysVIpcConfig *config, bool from_sigsys) {
	int status = 0;
	word_t timeout = 0;

	assert(config->wait_state == WSTATE_NOT_WAITING);

	word_t sysnum = get_sysnum(tracee, CURRENT);
	switch (sysnum) {
	case PR_msgget:
		status = sysvipc_msgget(tracee, config);
		break;
	case PR_msgsnd:
		status = sysvipc_msgsnd(tracee, config);
		break;
	case PR_msgrcv:
		status = sysvipc_msgrcv(tracee, config);
		break;
	case PR_msgctl:
		status = sysvipc_msgctl(tracee, config);
		break;
	case PR_semget:
		status = sysvipc_semget(tracee, config);
		break;
	case PR_semtimedop:
		timeout = peek_reg(tracee, CURRENT, SYSARG_4);
		// Fall-throug
	case PR_semop:
		status = sysvipc_semop(tracee, config);
		break;
	case PR_semctl:
		status = sysvipc_semctl(tracee, config);
		break;
	default:
		return 0;
	}

	if (config->wait_reason != WR_NOT_WAITING) {
		poke_reg(tracee, SYSARG_1, 0);
		poke_reg(tracee, SYSARG_2, 0);
		poke_reg(tracee, SYSARG_3, timeout);
		poke_reg(tracee, SYSARG_4, 0);
		set_sysnum(tracee, PR_ppoll);
		tracee->restart_how = PTRACE_SYSCALL;
		if (from_sigsys) {
			config->wait_state = WSTATE_RESTARTED_INTO_PPOLL;
			restart_syscall_after_seccomp(tracee);
			return 2;
		} else {
			config->wait_state = WSTATE_ENTERED_PPOLL;
			return 1;
		}
	} else {
		if (from_sigsys) {
			set_result_after_seccomp(tracee, status);
			return 2;
		} else {
			config->status_after_wait = status;
			config->wait_state = WSTATE_ENTERED_GETPID;
			set_sysnum(tracee, PR_getpid);
			tracee->restart_how = PTRACE_SYSCALL;
			return 1;
		}
	}
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int sysvipc_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	(void) data2;
	switch (event) {
	case INITIALIZATION:
	{
		struct SysVIpcConfig *config = talloc_zero(extension, struct SysVIpcConfig);
		config->ipc_namespace = talloc_zero(config, struct SysVIpcNamespace);
		extension->config = config;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT: /* Inheritable for sub reconfiguration ...  */
		return 1;

	case INHERIT_CHILD: {
		Extension *parent = (Extension *) data1;
		struct SysVIpcConfig *parent_config = parent->config;
		struct SysVIpcConfig *child_config = talloc_zero(extension, struct SysVIpcConfig);
		if (child_config == NULL)
			return -1;

		child_config->ipc_namespace = talloc_reference(child_config, parent_config->ipc_namespace);
		extension->config = child_config;

		return 0;
	}

	case SYSCALL_ENTER_START:
	{
		Tracee *tracee = TRACEE(extension);
		struct SysVIpcConfig *config = extension->config;
		switch (config->wait_state) {
		case WSTATE_NOT_WAITING:
			return sysvipc_syscall_common(tracee, config, false);
		case WSTATE_RESTARTED_INTO_PPOLL:
			assert(get_sysnum(tracee, CURRENT) == PR_ppoll);
			config->wait_state = WSTATE_ENTERED_PPOLL;
			tracee->restart_how = PTRACE_SYSCALL;
			return 1;
		case WSTATE_RESTARTED_INTO_PPOLL_CANCELED:
			poke_reg(tracee, SYSARG_RESULT, config->status_after_wait);
			set_sysnum(tracee, PR_void);
			config->wait_state = WSTATE_NOT_WAITING;
			return 1;
		default:
			assert(!"Bad wait_state on SYSCALL_ENTER_START");
		}
	}

	case SIGSYS_OCC:
	{
		Tracee *tracee = TRACEE(extension);
		struct SysVIpcConfig *config = extension->config;
		return sysvipc_syscall_common(tracee, config, true);
	}

	case SYSCALL_EXIT_START:
	{
		Tracee *tracee = TRACEE(extension);
		struct SysVIpcConfig *config = extension->config;
		switch (config->wait_state) {
		case WSTATE_NOT_WAITING:
			return 0;
		case WSTATE_ENTERED_PPOLL:
			assert(config->wait_state != WSTATE_NOT_WAITING);
			config->wait_state = WSTATE_NOT_WAITING;
			switch (config->wait_reason) {
			case WR_NOT_WAITING:
				assert(!"Unexpected wait_reason=WR_NOT_WAITING in SYSCALL_EXIT_START/WSTATE_ENTERED_PPOLL");
			case WR_WAIT_SEMOP:
				sysvipc_semop_timedout(tracee, config);
				break;
			default:
				config->wait_reason = WR_NOT_WAITING;
			}
			assert(config->wait_reason == WR_NOT_WAITING);
			if ((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) == -EFAULT) {
				return 1;
			}
			return -EAGAIN;
		case WSTATE_SIGNALED_PPOLL:
		case WSTATE_ENTERED_GETPID:
			config->wait_state = WSTATE_NOT_WAITING;
			poke_reg(tracee, SYSARG_RESULT, config->status_after_wait);
			return 1;
		default:
			assert(!"Bad wait_state on SYSCALL_EXIT_START");
		}
	}

	default:
		return 0;
	}
}

struct SysVIpcConfig *sysvipc_get_config(Tracee *tracee)
{
	Extension *extension = get_extension(tracee, sysvipc_callback);
	if (extension == NULL)
		return NULL;
	return talloc_get_type_abort(extension->config, struct SysVIpcConfig);
}

void sysvipc_wake_tracee(Tracee *tracee, struct SysVIpcConfig *config, int status)
{
	assert(config->wait_reason != WR_NOT_WAITING);
	config->wait_reason = WR_NOT_WAITING;
	config->status_after_wait = status;
	if (config->wait_state == WSTATE_ENTERED_PPOLL) {
		config->wait_state = WSTATE_SIGNALED_PPOLL;
		syscall(__NR_tkill, tracee->pid, 19);// TODO: SIGSTOP constant
	} else if (config->wait_state == WSTATE_RESTARTED_INTO_PPOLL) {
		config->wait_state = WSTATE_RESTARTED_INTO_PPOLL_CANCELED;
	} else {
		assert(!"Bad wait_state in sysvipc_wake_tracee");
	}
}
