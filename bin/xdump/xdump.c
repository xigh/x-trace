#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "../../sys/xtrace.h"

enum {
	BUFSZ = 4 * 1024 * 1024
};

int
main(int argc, char **argv, char **envv)
{
	int fd;
	struct xtrace_msg msg;
	char *buf;
	ssize_t l;
	
	if (argc < 2) {
		fprintf(stderr, "usage: xdump <trace-file>\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open xtrace.out");
		return -1;
	}

	for (;;) {
		l = read(fd, &msg, sizeof msg);
		if (l < 0) {
			perror("read");
			return -1;
		}

		if (l == 0) {
			break;
		}

		if (l != sizeof msg) {
			fprintf(stderr, "msg: invalid size returned: %zd\n", l);
			return -1;
		}

		buf = 0;
		if (msg.len > 0) {
			buf = (char *) malloc(msg.len);
			if (buf == 0) {
				perror("malloc");
				return -1;
			}
			
			l = read(fd, buf, msg.len);
			if (l < 0) {
				perror("read");
				return -1;
			}

			if (l != msg.len) {
				fprintf(stderr, "buf: invalid size returned: %zd\n", l);
				return -1;
			}
		}
		
		switch (msg.op) {
		case XTRACE_OP_FORK:
			printf("%5d: fork pid=%d\n", msg.pid, msg.arg0);
			break;
		case XTRACE_OP_EXIT:
			printf("%5d: exit rval=%d\n", msg.pid, msg.arg0);
			break;
		case XTRACE_OP_EXEC:
			printf("%5d: exec '%s' argc=%d envc=%d\n", msg.pid, buf ? buf : "", msg.arg0, msg.arg1);
			if (1) {
				int i;
				printf("\targv:\n");
				for (i = 0; i < msg.arg0; i += 1) {
					buf += strlen(buf) + 1;
					printf("\t  %2d: %s\n", i, buf);
				}
			}
			if (1) {
				int i;
				printf("\tenvv:\n");
				for (i = 0; i < msg.arg1; i += 1) {
					buf += strlen(buf) + 1;
					printf("\t  %2d: %s\n", i, buf);
				}
			}
			break;
		}

		if (buf != 0) {
			free(buf);
		}
	}
	
	close(fd);

	return 0;
}
