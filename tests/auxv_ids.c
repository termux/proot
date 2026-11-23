/* Print the credentials the ELF auxiliary vectors give the program,
 * and whether they announce a vDSO.
 *
 * "auxv_ids exec PROGRAM ARGS..." first makes an execve(2) of PROGRAM
 * the kernel refuses, with an argument too long (E2BIG), checks the
 * process still works, then runs PROGRAM.  */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/auxv.h>

int main(int argc, char *argv[])
{
	if (argc > 2 && strcmp(argv[1], "exec") == 0) {
		/* Longer than MAX_ARG_STRLEN.  */
		static char argument[200 * 1024];
		char *too_long[] = { argv[2], argument, NULL };

		memset(argument, 'x', sizeof(argument) - 1);
		execv(argv[2], too_long);
		if (errno != E2BIG) {
			perror("execv");
			return 1;
		}

		if (getcwd(argument, sizeof(argument)) == NULL) {
			perror("getcwd");
			return 1;
		}

		execv(argv[2], argv + 2);
		perror("execv");
		return 1;
	}

	printf("uid=%lu euid=%lu gid=%lu egid=%lu vdso=%d\n",
	       getauxval(AT_UID), getauxval(AT_EUID),
	       getauxval(AT_GID), getauxval(AT_EGID),
	       getauxval(AT_SYSINFO_EHDR) != 0);
	return 0;
}
