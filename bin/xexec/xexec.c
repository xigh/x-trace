#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../../sys/xtrace.h"

enum {
	BUFSZ = 4 * 1024 * 1024
};

struct proc {
	struct proc *link;
	int depth;
	int pid;
	int parent;
	char *wd;
};

struct proc *procMap[256];

struct proc *
getProc(int pid)
{
	int i, h;
	struct proc *p;

	h = pid % 256;
	p = procMap[h];
	while (p != 0) {
		if (p->pid == pid) {
			return p;
		}
		p = p->link;
	}
	p = (struct proc *) malloc(sizeof *p);
	if (p == 0) {
		return 0;
	}
	p->pid = pid;
	p->link = procMap[h];
	p->parent = 0;
	p->depth = 0;
	p->wd = strdup("?");
	procMap[h] = p;
	return p;
}

char*
escape(char *buf)
{
	static char *s = 0;
	static int ss = 0;
	int i, n;

	for (i = 0; buf[i] != 0; i++) {
		if (buf[i] == '"') {
			n++;
		}
	}
	if (n == 0) {
		return buf;
	}
	if (ss <= n+i) {
		if (s != 0) {
			free(s);
		}
		ss = n+i;
		s = (char *) malloc(ss+1);
		assert(s != 0);
	}
	for (n = i = 0; buf[i] != 0; i++, n++) {
		int c = buf[i];
		if (c == '"') {
			s[n] = '\\';
			n += 1;
		}
		s[n] = c;
	}
	s[n] = 0;
	return s;
}

int
main(int argc, char **argv, char **envv)
{
	int fd;
	struct xtrace_msg msg;
	char *buf;
	ssize_t l;
	int i, n, showEnvs;
	struct proc *p, *pp;

	showEnvs = 0;
	for (i = 1; i < argc; i ++) {
		if (strcmp(argv[i], "-e") == 0) {
			showEnvs = 1;
			continue;
		}
		break;
	}
	
	if (argc < 1 + i) {
		fprintf(stderr, "usage: xdump [-e] <trace-file>\n");
		return -1;
	}

	fd = open(argv[i], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", argv[i], strerror(errno));
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
			pp = getProc(msg.pid);
			if (pp != 0) {
				p = getProc(msg.arg0);
				if (p != 0) {
					p->parent = pp->pid;
					p->depth = pp->depth+1;
					if (p->wd) free(p->wd);
					p->wd = strdup(pp->wd);
				}
			}
			break;

		case XTRACE_OP_EXEC:
			p = getProc(msg.pid);
			if (p != 0) {
				for (n = 0; n < p->depth; n++)
					printf("  ");
				printf("%s:%s", p->wd, buf ? buf : "");
				for (int i = 0; i < msg.arg0; i += 1) {
					buf += strlen(buf) + 1;
					if (i > 0) {
						printf(" \"%s\"", escape(buf));
					}
				}
				printf("\n");
			}
			break;

		case XTRACE_OP_CHDIR:
			p = getProc(msg.pid);
			if (p != 0) {
				if (p->wd) free(p->wd);
				p->wd = strdup(buf ? buf : "");
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
