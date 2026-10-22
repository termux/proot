#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* Exit with the errno link(2) failed with, or 0.  */
int main(int argc, char **argv)
{
	if (argc < 3)
		return EXIT_FAILURE;

	return link(argv[1], argv[2]) == 0 ? EXIT_SUCCESS : errno;
}
