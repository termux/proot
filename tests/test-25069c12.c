#include <unistd.h> /* execve(2), */
#include <stdlib.h> /* exit(3), */
#include <string.h> /* strcmp(3), */

int main(int argc, char *argv[])
{
	char *void_array[] = { NULL };

	/* Since Linux 5.18 the kernel replaces an empty argv with
	 * { "", NULL }.  */
	if (argc == 0 || (argc == 1 && argv[0][0] == '\0'))
		exit(EXIT_SUCCESS);

	execve("/proc/self/exe", void_array, void_array);
	exit(EXIT_FAILURE);
}
