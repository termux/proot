#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* A thread other than the leader of its process calls execve(2): the
 * kernel gives the PID of the leader to that thread, without telling
 * the tracer that its former TID is gone.  */

static char *self;

static void *routine(void *unused)
{
	char *argv[] = { self, "execed", NULL };

	(void) unused;
	execv(self, argv);
	perror("execv");
	_exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	pthread_t thread;
	int child_status;
	pid_t pid;
	int status;

	if (argc > 1 && strcmp(argv[1], "execed") == 0) {
		if (syscall(SYS_gettid) != getpid()) {
			fprintf(stderr, "not the leader after execve(2)\n");
			exit(EXIT_FAILURE);
		}

		/* The process goes on under its former PID.  */
		pid = fork();
		if (pid < 0) {
			perror("fork");
			exit(EXIT_FAILURE);
		}
		if (pid == 0)
			exit(EXIT_SUCCESS);

		if (waitpid(pid, &child_status, 0) < 0) {
			perror("waitpid");
			exit(EXIT_FAILURE);
		}
		exit(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0
			? EXIT_SUCCESS : EXIT_FAILURE);
	}

	self = argv[0];

	status = pthread_create(&thread, NULL, routine, NULL);
	if (status != 0) {
		fprintf(stderr, "pthread_create: %s\n", strerror(status));
		exit(EXIT_FAILURE);
	}

	/* Killed by the execve(2) of the thread.  */
	while (1)
		pause();
}
