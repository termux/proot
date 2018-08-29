#ifndef FAKE_ID0_CHOWN_H
#define FAKE_ID0_CHOWN_H

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "extension/fake_id0/config.h"

int handle_chown_enter_end(Tracee *tracee, const Config *config, Reg uid_sysarg, Reg gid_sysarg);

#endif /* FAKE_ID0_CHOWN_H */
