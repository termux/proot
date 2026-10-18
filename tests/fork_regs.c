#define _GNU_SOURCE

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* Check that both sides of a fork(2) get back, with the values they had
 * before the syscall, the registers the kernel preserves across it.
 *
 *     fork_regs trap COMMAND [ARG...]
 *     fork_regs
 *
 * The first form runs COMMAND under a seccomp filter that raises SIGSYS on
 * fork(2), as Android's app policy does on x86_64, so that PRoot runs it as
 * clone(2), which takes arguments in these registers.  The second form does
 * the check with a raw fork(2).  Exit with 0 if it passed, with 125 where
 * there's no fork(2) or no seccomp filter (so the test is skipped) and with
 * 1 otherwise.  */

#if defined(__x86_64__)

#define FORK_ARCH AUDIT_ARCH_X86_64
#define NR_FORK 57

/* rdi, rsi, rdx, r10, r8, r9.  */
static const long expected[] = { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666 };

static long raw_fork(long regs[])
{
	long result;

	asm volatile ("mov $0x1111, %%rdi\n\t"
		      "mov $0x2222, %%rsi\n\t"
		      "mov $0x3333, %%rdx\n\t"
		      "mov $0x4444, %%r10\n\t"
		      "mov $0x5555, %%r8\n\t"
		      "mov $0x6666, %%r9\n\t"
		      "mov $57, %%eax\n\t"
		      "syscall\n\t"
		      "mov %%rdi, 0(%1)\n\t"
		      "mov %%rsi, 8(%1)\n\t"
		      "mov %%rdx, 16(%1)\n\t"
		      "mov %%r10, 24(%1)\n\t"
		      "mov %%r8, 32(%1)\n\t"
		      "mov %%r9, 40(%1)\n\t"
		      : "=&a" (result)
		      : "r" (regs)
		      : "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "memory");

	return result;
}

#elif defined(__i386__)

#define FORK_ARCH AUDIT_ARCH_I386
#define NR_FORK 2

/* ebx, ecx, edx, esi, edi, ebp.  */
static const long expected[] = { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666 };

static long raw_fork(long regs[])
{
	long result;

	asm volatile ("push %%ebp\n\t"
		      "push %%ebx\n\t"
		      "push %1\n\t"
		      "mov $0x1111, %%ebx\n\t"
		      "mov $0x2222, %%ecx\n\t"
		      "mov $0x3333, %%edx\n\t"
		      "mov $0x4444, %%esi\n\t"
		      "mov $0x5555, %%edi\n\t"
		      "mov $0x6666, %%ebp\n\t"
		      "mov $2, %%eax\n\t"
		      "int $0x80\n\t"
		      "xchg %%eax, (%%esp)\n\t"
		      "mov %%ebx, 0(%%eax)\n\t"
		      "mov %%ecx, 4(%%eax)\n\t"
		      "mov %%edx, 8(%%eax)\n\t"
		      "mov %%esi, 12(%%eax)\n\t"
		      "mov %%edi, 16(%%eax)\n\t"
		      "mov %%ebp, 20(%%eax)\n\t"
		      "pop %%eax\n\t"
		      "pop %%ebx\n\t"
		      "pop %%ebp\n\t"
		      : "=a" (result)
		      : "r" (regs)
		      : "ecx", "edx", "esi", "edi", "memory");

	return result;
}

#elif defined(__arm__) && !defined(__thumb__)

#define FORK_ARCH AUDIT_ARCH_ARM
#define NR_FORK 2

/* r1-r6, then r7: the syscall number.  */
static const long expected[] = { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 2 };

static long raw_fork(long regs[])
{
	register long *base asm("r8") = regs;
	long result;

	asm volatile ("push {r4, r5, r6, r7}\n\t"
		      "ldr r1, =0x1111\n\t"
		      "ldr r2, =0x2222\n\t"
		      "ldr r3, =0x3333\n\t"
		      "ldr r4, =0x4444\n\t"
		      "ldr r5, =0x5555\n\t"
		      "ldr r6, =0x6666\n\t"
		      "mov r7, #2\n\t"
		      "svc #0\n\t"
		      "str r1, [r8, #0]\n\t"
		      "str r2, [r8, #4]\n\t"
		      "str r3, [r8, #8]\n\t"
		      "str r4, [r8, #12]\n\t"
		      "str r5, [r8, #16]\n\t"
		      "str r6, [r8, #20]\n\t"
		      "str r7, [r8, #24]\n\t"
		      "pop {r4, r5, r6, r7}\n\t"
		      "mov %0, r0\n\t"
		      "b 1f\n\t"
		      ".ltorg\n"
		      "1:\n\t"
		      : "=r" (result)
		      : "r" (base)
		      : "r0", "r1", "r2", "r3", "memory");

	return result;
}

#endif

#ifdef FORK_ARCH

#define NB_REGS (sizeof(expected) / sizeof(expected[0]))

static int trap_fork(char *argv[])
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FORK_ARCH, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_FORK, 0, 1),
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
}

int main(int argc, char *argv[])
{
	long regs[NB_REGS];
	bool ok = true;
	long pid;
	int status;
	size_t i;

	if (argc > 2 && strcmp(argv[1], "trap") == 0)
		return trap_fork(argv + 2);

	pid = raw_fork(regs);
	if (pid < 0) {
		fprintf(stderr, "fork: %s\n", strerror(-pid));
		return 1;
	}

	for (i = 0; i < NB_REGS; i++) {
		if (regs[i] != expected[i]) {
			fprintf(stderr, "%s: register #%zu is 0x%lx instead of 0x%lx\n",
				pid == 0 ? "child" : "parent", i, regs[i], expected[i]);
			ok = false;
		}
	}

	if (pid == 0)
		_exit(ok ? 42 : 1);

	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
		ok = false;

	return ok ? 0 : 1;
}

#else

int main(void)
{
	return 125;
}

#endif
