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
"userns-file must be the following type of file: /proc/<pid>/ns/user\n"
"\n", prg);
}

int main(int argc, const char *argv[])
{
	int fd, ret;
	char buffer[1024], *bufp = buffer;
	size_t size = sizeof(buffer);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open file %s: %s\n",
			argv[1], strerror(errno));
		return 1;
	}

	ret = syscall(328, fd, buffer, size);
	if (ret != 0) {
		fprintf(stderr, "Syscall failed: %s (errno: %d)\n",
			strerror(errno), errno);
	}

	while (ret > 0) {
		printf("xattr: %s\n", bufp);
		ret -= (strlen(bufp) + 1);
		bufp += strlen(bufp) + 1;
	}

	close(fd);
	return 0;
}
