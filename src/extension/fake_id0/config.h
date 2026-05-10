#ifndef FAKE_ID0_CONFIG_H
#define FAKE_ID0_CONFIG_H

#include <sys/types.h>   /* uid_t, gid_t */

typedef struct {
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;

	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;

	mode_t umask;

	/* Effective UID at the time this fake_id0 config was created.  When
	 * non-zero, it means the process was spawned with a specific fake
	 * identity.  When zero (proot -0), the process started as fake root
	 * and credential changes must always be allowed regardless of the
	 * current fake euid, because proot -0 permanently grants
	 * CAP_SETUID/CAP_SETGID semantics. */
	uid_t initial_euid;
} Config;

#endif /* FAKE_ID0_CONFIG_H */
