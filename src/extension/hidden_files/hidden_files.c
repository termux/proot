/*
 * Author: Dieter Mueller
 * Date:   6/12/2015
 *
 * Description: An extension to allow getdents to hide files
 * with a given prefix. Useful for keeping files from being
 * deleted by wildcard expressions.
 */

#include <string.h>
#include <talloc.h>

#include "extension/extension.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "syscall/chain.h"
#include "path/path.h"

/* Change the HIDDEN_PREFIX to change which files are hidden */
#define HIDDEN_PREFIX ".proot"

/*
 * Blind copies the given num of bytes from src to dst
 */
static void mybcopy(char *src, char *dst, unsigned int num) {
    while(num--) { *(dst++) = *(src++); }
}

/*
 * Compares the given prefix with the given string.
 * If str has the given prefix, return 1. Otherwise
 * return 0
 */

static int hasprefix(char *prefix, char *str) {
    while (*prefix && *str && (*(prefix) == *(str))) {
        prefix++;
        str++;
    }
  
    /* If there is not any prefix left after stepping
     * through the strings, then it matches */
    if (!(*prefix)) { return 1; }
    return 0;
}

/**
 * Hide all files with a given PREFIX so they don't exist to
 * the user
 */
static int handle_getdents(Tracee *tracee)
{
    switch (get_sysnum(tracee, ORIGINAL)) {
    case PR_getdents64: 
    case PR_getdents: {
        /* get the result of the syscall, which is the number of bytes read by getdents,
         * or -errno: there is nothing to hide then.  It used to be read as unsigned,
         * so an error was taken for a huge size, and that many bytes were copied into
         * the buffer below -- PRoot crashed whenever getdents failed.  */
        int res = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (res <= 0) {
            return 0;
        }

        /* get the system call arguments */
        word_t orig_start = peek_reg(tracee, CURRENT, SYSARG_2);
        unsigned int count = peek_reg(tracee, CURRENT, SYSARG_3);

        /* Only the bytes the kernel filled matter, and count -- chosen by the
         * tracee -- is no size for buffers on the stack.  */
        char *orig = talloc_size(tracee->ctx, res);
        char *copy = talloc_size(tracee->ctx, res);
        if (orig == NULL || copy == NULL) {
            return 0;
        }

        /* Where d_reclen and d_name lie in each record.  The d_ino and d_off of
         * struct linux_dirent64 are 64-bit whatever the ABI.  Those of struct
         * linux_dirent are a word of the ABI of the tracee -- not of PRoot: they
         * are half as large for a 32-bit tracee of a 64-bit PRoot -- and its
         * d_type is the last byte of the record.  */
        size_t reclen_offset;
        size_t name_offset;
        if (get_sysnum(tracee, ORIGINAL) == PR_getdents64) {
            reclen_offset = 16;
            name_offset = 19;
        } else {
            reclen_offset = 2 * sizeof_word(tracee);
            name_offset = reclen_offset + 2;
        }

        char path[PATH_MAX];
        int status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, ORIGINAL, SYSARG_1), path);
        if (status < 0) {
           return 0;
        }
        if(!belongs_to_guestfs(tracee, path))
           return 0;

        /* retrieve the data from getdents */
        status = read_data(tracee, orig, orig_start, res);
        if (status < 0) {
            return status;
        }

        /* offset keeps track of where in memory the original is */
        size_t offset = 0;
        /* nleft keeps track of how many bytes we've saved */
        unsigned int nleft = 0;

        /* while we're still within the memory allowed */
        while (offset < (size_t) res) {
            unsigned short reclen;
            char *name;

            /* Leave a listing that can't be parsed as it is, rather than loop
             * forever on a null d_reclen or read past the buffer.  */
            if (offset + name_offset >= (size_t) res) {
                return 0;
            }
            memcpy(&reclen, orig + offset + reclen_offset, sizeof(reclen));
            if (reclen <= name_offset || reclen > (size_t) res - offset) {
                return 0;
            }
            name = orig + offset + name_offset;
            if (memchr(name, '\0', reclen - name_offset) == NULL) {
                return 0;
            }

            /* if the name does not matche a given prefix */
            if (!hasprefix(HIDDEN_PREFIX, name)) {

                /* copy the information */
                mybcopy(orig + offset, copy + nleft, reclen);

                /* move nleft */
                nleft += reclen;
            }
            /* move to the next record */
            offset += reclen;
        }
        /* If there is nothing left */
        if (!nleft) {
            /* call getdents again */
            if (get_sysnum(tracee, ORIGINAL) == PR_getdents64)
                register_chained_syscall(tracee, PR_getdents64, peek_reg(tracee, ORIGINAL, SYSARG_1), orig_start, count, 0, 0, 0);
            else
                register_chained_syscall(tracee, PR_getdents, peek_reg(tracee, ORIGINAL, SYSARG_1), orig_start, count, 0, 0, 0);
        }
        else {
            /* copy the data back into the register */
            status = write_data(tracee, orig_start, copy, nleft);
            if (status < 0) {
                return status;
            }
            /* update the return value to match the data */
            poke_reg(tracee, SYSARG_RESULT, nleft);
        }

        /* return successful */
        return 0;
    }

    default:
        return 0;
    }
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int hidden_files_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* List of syscalls handled by this extension */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_getdents,    FILTER_SYSEXIT },
            { PR_getdents64,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END: {
        return handle_getdents(TRACEE(extension));
    }

    default:
        return 0;
    }
}
