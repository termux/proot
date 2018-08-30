/** Convert fstat and fstat64 to readlink
 *  this is so we can get the path associated with /proc/pid#/fd/fd#
 */
#include <linux/limits.h>

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"

#include "shared_structs.h"

int handle_fstat_enter(Tracee *tracee, Reg fd_sysarg) {
    char path[PATH_MAX];
    char link_path[64];
    word_t link_address;
    word_t path_address;

    set_sysnum(tracee, PR_readlinkat);
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", tracee->pid, (int)peek_reg(tracee, CURRENT, fd_sysarg));
    link_address = alloc_mem(tracee, sizeof(link_path));
    path_address = alloc_mem(tracee, sizeof(path));
    write_data(tracee, link_address, link_path, sizeof(link_path));
    write_data(tracee, path_address, path, sizeof(path));
    poke_reg(tracee, SYSARG_1, AT_FDCWD);    
    poke_reg(tracee, SYSARG_2, link_address);    
    poke_reg(tracee, SYSARG_3, path_address);    
    poke_reg(tracee, SYSARG_4, sizeof(path));    
    return 0;
}
