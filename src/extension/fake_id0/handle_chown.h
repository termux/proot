#ifndef HANDLE_CHOWN_H_
#define HANDLE_CHOWN_H_

#include "shared_structs.h"

extern int handle_chown(Tracee *tracee, Reg path_sysarg, Reg owner_sysarg, Reg group_sysarg, Reg fd_sysarg, Reg dirfd_sysarg, Config *config);

#endif
