#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void usage(const char *prg)
{
	fprintf(stderr,
"Usage: %s xattr userns-file\n"
""
"Supported xattr are: security.ima\n"
"userns-file must be the following type of file: /proc/<pid>/ns/user\n"
"\n", prg);
}

int main(int argc, const char *argv[])
{
	int fd, ret;

	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open file %s: %s\n",
			argv[2], strerror(errno));
		return 1;
	}

	ret = syscall(327, argv[1], fd);
	if (ret != 0) {
		fprintf(stderr, "Syscall failed: %s (errno: %d)\n",
			strerror(errno), errno);
	}

	close(fd);
	return 0;
}
