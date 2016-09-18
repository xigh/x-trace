#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

#include "../../sys/xtrace.h"

enum {
	BUFSZ = 4 * 1024 * 1024
};

int
main(int argc, char **argv, char **envv)
{
	int devfd, outfd, pid, wpid, s;
	struct xtrace_msg *msg;
	ssize_t l, lo;
	
	if (argc < 2) {
		fprintf(stderr, "usage: xtrace <prog> [args ...]\n");
		return -1;
	}
	
	msg = (struct xtrace_msg *) malloc(BUFSZ);
	if (!msg) {
		perror("malloc");
		return -1;
	}

	devfd = open("/dev/xtrace", O_RDONLY);
	if (devfd < 0) {
		perror("open /dev/xtrace");
		return -1;
	}

	outfd = open("xtrace.out", O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (outfd < 0) {
		perror("open xtrace.out");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		sleep(1);
		
		s = execve(argv[1], argv + 1, envv);
		if (s < 0) {
			perror("execve");
		}
		exit(-1);
	}

	printf("started pid %d\n", pid);

	for (;;) {
		l = read(devfd, msg, BUFSZ);
		if (l < 0) {
			perror("read");
			return -1;
		}

		if (l < sizeof *msg) {
			fprintf(stderr, "invalid size returned: %lld\n", 
				(long long) l);
			return -1;
		}
		
		lo = write(outfd, msg, l);
		if (lo < 0) {
			perror("write");
			return -1;
		}

		if (lo != l) {
			fprintf(stderr, "write error: %lld != %lld\n", 
				(long long) lo, (long long) l);
			return -1;
		}

		if (msg->pid == pid && msg->op == XTRACE_OP_EXIT)
			break;
	}
	
	wpid = wait(&s);
	if (wpid < 0) {
		perror("wait");
		return -1;
	}

	printf("child returned with %d\n", s);

	if (wpid != pid) {
		fprintf(stderr, "fatal: unexpected child exit");
		return -1;
	}
	
	close(devfd);

	return 0;
}
