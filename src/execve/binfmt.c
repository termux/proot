#include "execve/binfmt.h"
#include "execve/execve.h"
#include "execve/aoxp.h"
#include "tracee/reg.h"
#include "tracee/tracee.h"
#include "cli/note.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

BinfmtRule* rules = NULL;
int rules_number = 0;

int register_binfmt(const BinfmtRule* rule) {
	if (!rules) {
		rules = malloc(sizeof(BinfmtRule));
		if (!rules) {
			return -ENOMEM;
		}
	} else {
		BinfmtRule* new_rules = realloc(rules, sizeof(BinfmtRule) * (rules_number + 1));
		if (!new_rules) {
			return -ENOMEM;
		}
		rules = new_rules;
	}
	BinfmtRule r = *rule;
	// Ensure mask is applied to magic
	if (r.type == 'M') {
		for (size_t i = 0; i < PATH_MAX; i++) {
			r.magic[i] &= r.mask[i];
		}
	}
	// Add the new rule to the array
	rules[rules_number++] = r;
	return 0;
}

int unregister_binfmt(const char *name) {
	if (!rules || rules_number == 0) {
		return -ENOENT;
	}
	for (int i = 0; i < rules_number; i++) {
		if (strcmp(rules[i].name, name) == 0) {
			// Found the rule, remove it
			for (int j = i; j < rules_number - 1; j++) {
				rules[j] = rules[j + 1];
			}
			rules_number--;
			return 0;
		}
	}
	return -ENOENT;
}

// Helper function to process escape sequences in strings
static size_t process_escape_sequences(const char *src, char *dst, size_t max_len) {
	if (!src || !dst) return 0;
	
	size_t len = 0;
	const char *ptr = src;
	
	while (*ptr && len < max_len) {
		if (*ptr == '\\') {
			ptr++;
			if (*ptr == '\0') break;
			
			if (*ptr == 'n') {
				*dst++ = '\n';
				len++;
			} else if (*ptr == 't') {
				*dst++ = '\t';
				len++;
			} else if (*ptr == 'r') {
				*dst++ = '\r';
				len++;
			} else if (*ptr == '\\') {
				*dst++ = '\\';
				len++;
			} else if (*ptr == 'x') {
				ptr++;
				char hex[3] = {0};
				if (isxdigit(ptr[0])) hex[0] = *ptr++;
				if (isxdigit(ptr[0])) hex[1] = *ptr++;
				if (hex[0]) {
					*dst++ = (char)strtol(hex, NULL, 16);
					len++;
				}
				continue;  // ptr already advanced
			} else {
				*dst++ = *ptr;
				len++;
			}
		} else {
			*dst++ = *ptr;
			len++;
		}
		ptr++;
	}
	
	return len;
}

int read_binfmt_rules_from_file(const char *filepath) {
	FILE *file = fopen(filepath, "r");
	if (!file) {
		note(NULL, ERROR, SYSTEM, "Failed to open binfmt configuration file");
		return -1;
	}
	// Read file line by line
	char line[4096];
	int line_num = 0;
	int errors = 0;
	const char* slash = strrchr(filepath, '/');
	const char* filename = slash ? slash + 1 : filepath;
	while (fgets(line, sizeof(line), file)) {
		line_num++;
		line[strcspn(line, "\n")] = 0; // Remove newline
		BinfmtRule rule = {0};
		memset(&rule, 0, sizeof(BinfmtRule));
		// Parse line (:name:type:offset:magic:mask:interpreter:)
		char* p = line;
		strsep(&p, ":");
		char* pname = strsep(&p, ":");
		char* ptype = strsep(&p, ":");
		char* poffset = strsep(&p, ":");
		char* pmagic = strsep(&p, ":");
		char* pmask = strsep(&p, ":");
		char* pinterp = strsep(&p, ":");
		
		// Validate all required fields are present
		if (!pname || !ptype || !poffset || !pmagic || !pmask || !pinterp) {
			note(NULL, ERROR, USER, "%s:%d: missing fields", filename, line_num);
			errors++;
			continue;
		}
		
		if (strlen(ptype) != 1) {
			note(NULL, ERROR, USER, "%s:%d: invalid type", filename, line_num);
			errors++;
			continue;
		}
		
		if (ptype[0] != 'M' && ptype[0] != 'E') {
			note(NULL, ERROR, USER, "%s:%d: type must be 'M' or 'E'", filename, line_num);
			errors++;
			continue;
		}
		
		strncpy(rule.name, pname, sizeof(rule.name) - 1);
		rule.name[sizeof(rule.name) - 1] = '\0';
		rule.type = ptype[0];
		rule.offset = atoi(poffset);
		// Process escape sequences in magic, mask, and interpreter
		size_t magic_len = process_escape_sequences(pmagic, rule.magic, PATH_MAX);
		
		if (*pmask == '\0') {
			// Empty mask means all bits should be checked (0xFF)
			memset(rule.mask, 0xFF, magic_len);
		} else {
			process_escape_sequences(pmask, rule.mask, PATH_MAX);
		}
		
		size_t interp_len = process_escape_sequences(pinterp, rule.interpreter, PATH_MAX);
		
		if (magic_len == 0 || interp_len == 0) {
			note(NULL, ERROR, USER, "%s:%d: invalid %s or interpreter", filename, line_num, rule.type == 'M' ? "magic" : "extension");
			errors++;
			continue;
		}

		// Register rule
		if (errors == 0) {
			int status = register_binfmt(&rule);
			if (status < 0) {
				note(NULL, ERROR, INTERNAL, "Failed to register binfmt rule: %s", strerror(-status));
				return -1;
			}
		}
		line_num++;
	}
	if (errors) {
		note(NULL, ERROR, USER, "%s: %d errors found", filename, errors);
		return -1;
	}
	fclose(file);
	return 0;
}

void clear_binfmt_rule_list() {
	free(rules);
	rules = NULL;
	rules_number = 0;
}

int check_binfmt(Tracee *tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]) {
	ArrayOfXPointers *argv = NULL;
	bool has_matched = false;
	BinfmtRule* r = NULL;
	int status = 0;
	char* old_user_path = NULL;

	old_user_path = talloc_strdup(tracee->ctx, user_path);
	if (!old_user_path) {
		return -ENOMEM;
	}
	for (int i = 0; i < rules_number; i++) {
		r = &rules[i];
		if (r->type == 'E') {
			size_t path_len = strlen(user_path);
			size_t ext_len = strlen(r->magic);

			if (ext_len > path_len) continue;
			if (strcmp(user_path + path_len - ext_len, r->magic) == 0) {
				has_matched = true;
				break;
			}
		}
		if (r->type == 'M') {
			// Find last 1 in the mask
			size_t mask_size = 0;
			for (int k = PATH_MAX - 1; k >= 0; k--) {
				if (r->mask[k] != 0) {
					mask_size = k + 1;
					break;
				}
			}
			if (mask_size == 0) continue;
			// Read magic number from file
			char* magic = talloc_array(tracee->ctx, char, mask_size);
			if (!magic) {
				talloc_free(old_user_path);
				return -ENOMEM;
			}
			int fd = open(host_path, O_RDONLY);
			if (fd < 0) {
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			if (lseek(fd, r->offset, SEEK_SET) < 0) {
				close(fd);
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			ssize_t rr = read(fd, magic, mask_size);
			if (rr < 0) {
				close(fd);
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			if ((size_t)rr < mask_size) {
				/* Not enough bytes in file */
				talloc_free(magic);
				continue;
			}
			close(fd);
			// Apply mask and compare
			for (size_t j = 0; j < mask_size; j++) {
				magic[j] &= r->mask[j];
			}
			if (memcmp(magic, r->magic, mask_size) == 0) {
				has_matched = true;
				talloc_free(magic);
				break;
			}
			talloc_free(magic);
		}
	}

	if (has_matched) {
		// Rule matched, modify path and arguments

		// Note: The interpreter path is not tokenized;
		// the entire string is used as the interpreter path.
		strcpy(user_path, r->interpreter);
		status = translate_and_check_exec(tracee, host_path, user_path);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}
		// Fetch argv[] only on demand.
		if (argv == NULL) {
			status = fetch_array_of_xpointers(tracee, &argv, SYSARG_2, 0);
			if (status < 0) {
				talloc_free(old_user_path);
				return status;
			}
		}
		// Add interpreter to argv
		status = resize_array_of_xpointers(argv, 0, 1 + (argv->length == 1));
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}
		status = write_xpointees(argv, 0, 2, user_path, old_user_path);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}

		// Push args
		status = push_array_of_xpointers(argv, SYSARG_2);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}

		talloc_free(old_user_path);
		return 1;
	}

	talloc_free(old_user_path);
	return 0;
}
