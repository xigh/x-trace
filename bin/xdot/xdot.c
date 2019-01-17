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

struct proc {
	struct proc *next;
	struct proc *parent;
	char *name;
	int argc;
	char **argv;
	char **envv;
	int pid;
	int n;
};

char* arg(struct proc *p) {
	char *b, *s;
	int i, j;

	s = b = malloc(32 * 1024);
	if (b == 0) {
		perror("malloc");
		exit(-1);
	}

	s += sprintf(s, "%d:%s\\n", p->n, p->name);
	for (i = 0; i < p->argc; i += 1) {
		char *a = p->argv[i];
		for (j = 0; a[j] != 0; j += 1) {
			if (a[j] == '"') {
				a[j] = '\'';
			}
			if (j > 24) {
				a[j - 3] = '.';
				a[j - 2] = '.';
				a[j - 1] = '.';
				a[j] = 0;
				break;
			}
		}
		s += sprintf(s, "%d:%s\\n", i, a);
	}

	return b;
}

struct proc *procs = 0;
int nprocs = 0;

struct proc * findp(int pid) {
	struct proc *p;

	for (p = procs; p != 0; p = p->next) {
		if (p->pid == pid)
			return p;
	}
	return 0;
}

int main(int argc, char **argv) {
	int i, fd;
	struct xtrace_msg msg;
	char *buf;
	ssize_t l;
	struct proc *p, *q;
	
	if (argc < 2) {
		fprintf(stderr, "usage: xdump <trace-file>\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open xtrace.out");
		return -1;
	}

	printf("digraph G {\n");
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
			p = (struct proc *) malloc(sizeof *p);
			if (p == 0) {
				perror("malloc");
				return -1;
			}
			p->n = nprocs;
			nprocs += 1;
			p->parent = findp(msg.pid);
			p->pid = msg.arg0;
			p->next = procs;
			procs = p;
			// printf("%5d: fork pid=%d\n", msg.pid, msg.arg0);
			break;
		case XTRACE_OP_EXIT:
			// printf("%5d: exit rval=%d\n", msg.pid, msg.arg0);
			break;
		case XTRACE_OP_EXEC:
			p = findp(msg.pid);
			if (p) {
				p->name = strdup(buf);
				p->argc = msg.arg0;
				p->argv = malloc(msg.arg0 * sizeof(char *));
				if (p->argv == 0) {
					perror("malloc");
					return -1;
				}
				for (i = 0; i < msg.arg0; i += 1) {
					buf += strlen(buf) + 1;
					p->argv[i] = strdup(buf);
				}
				q = p->parent;
				if (q && q->name) {
					char *u, *v;

					u = arg(q);
					v = arg(p);
					printf("\t\"%s\" -> \"%s\"\n", u, v);
					free(u);
					free(v);
				}
			}
			/*
			printf("%5d: exec '%s' argc=%d envc=%d\n", msg.pid,
			       buf ? buf : "", msg.arg0, msg.arg1);
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
			*/
			break;
		}

		if (buf != 0) {
			free(buf);
		}
	}
	printf("}\n");
	
	close(fd);

	return 0;
}
