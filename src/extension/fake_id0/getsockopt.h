#ifndef FAKE_ID0_GETSOCKOPT_H
#define FAKE_ID0_GETSOCKOPT_H

#include <stdbool.h>

#include "tracee/tracee.h"
#include "arch.h"

bool is_peercred_getsockopt(const Tracee *tracee, word_t *optval);
int handle_getsockopt_exit_end(Tracee *tracee);

#endif /* FAKE_ID0_GETSOCKOPT_H */
