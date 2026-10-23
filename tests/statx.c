#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/stat.h>

/* Call statx(2) directly, as C libraries pick their own stat syscall:
 * glibc 2.33+ uses statx for stat(3) on 32-bit ABIs, fstatat on 64-bit
 * ones, and coreutils calls statx itself.
 *
 *     statx [-n] [-c FILE] PATH
 *     statx trap COMMAND [ARG...]
 *
 * The first form prints the permission bits of PATH in octal, or the name
 * of the error.  With -n the flags are AT_SYMLINK_NOFOLLOW.  With -c, FILE
 * is chmod(2)ed to 0600 just before.  The second form runs COMMAND under a
 * seccomp filter that raises SIGSYS on statx(2) of the ABI of this
 * program, as Android's app policy does before Android 11.  Exit with 0 if
 * the syscall succeeded, with 125 if the kernel doesn't know it or there's
 * no seccomp filter (so the test is skipped) and with 1 otherwise.  */

#if defined(__x86_64__)
#define STATX_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define STATX_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define STATX_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define STATX_ARCH AUDIT_ARCH_ARM
#endif

static int trap_statx(char *argv[])
{
#ifdef STATX_ARCH
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STATX_ARCH, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_statx, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
	    || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0) {
		perror("seccomp");
		return 125;
	}

	execvp(argv[0], argv);
	perror("execvp");
	return 1;
#else
	(void) argv;
	return 125;
#endif
}

int main(int argc, char *argv[])
{
	struct statx statx_buf;
	const char *chmod_path = NULL;
	int flags = 0;
	int status;
	int opt;

	if (argc > 2 && strcmp(argv[1], "trap") == 0)
		return trap_statx(argv + 2);

	while ((opt = getopt(argc, argv, "nc:")) != -1) {
		switch (opt) {
		case 'n':
			flags = AT_SYMLINK_NOFOLLOW;
			break;
		case 'c':
			chmod_path = optarg;
			break;
		default:
			return 1;
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, "usage: statx [-n] [-c FILE] PATH\n");
		return 1;
	}

	if (chmod_path != NULL && chmod(chmod_path, 0600) < 0) {
		perror("chmod");
		return 1;
	}

	memset(&statx_buf, 0, sizeof(statx_buf));
	status = syscall(SYS_statx, AT_FDCWD, argv[optind], flags, STATX_MODE, &statx_buf);
	if (status < 0) {
		switch (errno) {
		case ENOSYS:
			return 125;
		case EACCES:
			puts("EACCES");
			break;
		case ENOENT:
			puts("ENOENT");
			break;
		default:
			printf("errno %d\n", errno);
			break;
		}
		return 1;
	}

	if ((statx_buf.stx_mask & STATX_MODE) == 0) {
		puts("no STATX_MODE");
		return 1;
	}

	printf("%o\n", statx_buf.stx_mode & 07777);
	return 0;
}
