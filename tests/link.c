#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 3)
		return EXIT_FAILURE;

	return link(argv[1], argv[2]) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
