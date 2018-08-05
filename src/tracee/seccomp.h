#include "tracee/tracee.h"

int handle_seccomp_event(Tracee* tracee);
void fix_and_restart_enosys_syscall(Tracee* tracee);
