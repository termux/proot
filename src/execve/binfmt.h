#ifndef BINFMT_H
#define BINFMT_H

#include <stddef.h>
#include <linux/limits.h>

#include "tracee/tracee.h"

typedef struct {
    char name[256];
    char type; // M for magic number, E for extension
    size_t offset;
    char magic[PATH_MAX];
    char mask[PATH_MAX];
    char interpreter[PATH_MAX];
} BinfmtRule;

int register_binfmt(const BinfmtRule* rule);
int unregister_binfmt(const char* name);
int read_binfmt_rules_from_file(const char* filepath);
void clear_binfmt_rule_list();

int check_binfmt(Tracee* tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]);

#endif
