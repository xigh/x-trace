/*-
 * Copyright (c) 2013-2016 Philippe Anel. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/imgact.h>

#include "xtrace.h"

MALLOC_DEFINE(M_XTRACE_PID, "xtrpid", "xtrace process id");

static struct mtx xtrace_pid_mtx;
MTX_SYSINIT(xtrace_pid_mtx, &xtrace_pid_mtx, "xtrace_pid", MTX_DEF);

static int xtrace_pid_adds = 0;
static int xtrace_pid_dels = 0;
struct xtrace_pid_entry
{
	TAILQ_ENTRY(xtrace_pid_entry)
	entries;
	int pid;
};
static TAILQ_HEAD(, xtrace_pid_entry) xtrace_pid_head =
	TAILQ_HEAD_INITIALIZER(xtrace_pid_head);

static int xtrace_opened = 0;

static void xtrace_add_pid(int pid, char *reason)
{
	struct xtrace_pid_entry *item, *tmp;
	int found;

	printf("xtrace: add pid %d (%s)\n", pid, reason);

	item = (struct xtrace_pid_entry *)
		malloc(sizeof *item, M_XTRACE_PID, M_NOWAIT);
	if (!item)
	{
		printf("xtrace: add_pid: malloc failed\n");
		return;
	}
	item->pid = pid;
	found = 0;
	mtx_lock(&xtrace_pid_mtx);
	TAILQ_FOREACH(tmp, &xtrace_pid_head, entries)
	{
		if (tmp->pid == pid)
		{
			found = 1;
			break;
		}
	}
	if (!found)
	{
		TAILQ_INSERT_TAIL(&xtrace_pid_head, item, entries);
		xtrace_pid_adds += 1;
	}
	mtx_unlock(&xtrace_pid_mtx);
	if (found)
		free(item, M_XTRACE_PID);
}

static void xtrace_remove_pid(int pid)
{
	struct xtrace_pid_entry *item, *tmp;

	printf("xtrace: remove pid %d (exit)\n", pid);

	item = 0;
	mtx_lock(&xtrace_pid_mtx);
	TAILQ_FOREACH(tmp, &xtrace_pid_head, entries)
	{
		if (tmp->pid == pid)
		{
			item = tmp;
			TAILQ_REMOVE(&xtrace_pid_head, item, entries);
			break;
		}
	}

	mtx_unlock(&xtrace_pid_mtx);
	if (item)
	{
		xtrace_pid_dels += 1;
		free(item, M_XTRACE_PID);
	}
}

static int xtrace_is_pid_logged(int pid)
{
	struct xtrace_pid_entry *tmp;
	int found;

	found = 0;
	mtx_lock(&xtrace_pid_mtx);
	TAILQ_FOREACH(tmp, &xtrace_pid_head, entries)
	{
		if (tmp->pid == pid)
		{
			found = 1;
			break;
		}
	}
	mtx_unlock(&xtrace_pid_mtx);

	return found;
}

MALLOC_DEFINE(M_XTRACE_MSG, "xtrmsg", "xtrace message");

static int xtrace_msg_chan = 0;
static struct mtx xtrace_msg_mtx;
MTX_SYSINIT(xtrace_msg_mtx, &xtrace_msg_mtx, "xtrace_msg", MTX_DEF);

static int xtrace_msg_adds = 0;
static int xtrace_msg_dels = 0;
struct xtrace_msg_entry
{
	TAILQ_ENTRY(xtrace_msg_entry)
	entries;
	struct xtrace_msg msg;
};
static TAILQ_HEAD(, xtrace_msg_entry) xtrace_msg_head =
	TAILQ_HEAD_INITIALIZER(xtrace_msg_head);

static int thrpid(struct thread *td)
{
	struct proc *p;

	if (td == 0)
		return -1;

	p = td->td_proc;
	if (p == 0)
		return -1;

	return p->p_pid;
}

static void xtrace_log(struct thread *td, int op, int arg0, int arg1, int arg2, int len, void *buf)
{
	struct xtrace_msg_entry *item;
	struct bintime bt;
	int pid;

	pid = thrpid(td);
	if (!xtrace_is_pid_logged(pid))
		return;

	item = (struct xtrace_msg_entry *)malloc(len + sizeof *item, M_XTRACE_MSG, M_NOWAIT);
	if (item == 0)
	{
		printf("%5d: xtrace: malloc failed\n", pid);
		return;
	}

	item->msg.op = op;
	item->msg.pid = pid;
	item->msg.len = len;
	item->msg.arg0 = arg0;
	item->msg.arg1 = arg1;
	item->msg.arg2 = arg2;
	if (len > 0)
	{
		memcpy(item->msg.buf, buf, len);
	}

	getbinuptime(&bt);
	item->msg.ms = bt.sec * 1000;
	item->msg.ms += ((uint64_t)1000 * (uint32_t)(bt.frac >> 32)) >> 32;

	mtx_lock(&xtrace_msg_mtx);
	xtrace_msg_adds += 1;
	TAILQ_INSERT_TAIL(&xtrace_msg_head, item, entries);
	wakeup(&xtrace_msg_chan);
	mtx_unlock(&xtrace_msg_mtx);

	switch (op)
	{
	case XTRACE_OP_FORK:
		xtrace_add_pid(arg0, "fork");
		break;

	case XTRACE_OP_EXIT:
		xtrace_remove_pid(pid);
		break;
	}
}

static d_open_t xtrace_open;
static d_close_t xtrace_close;
static d_read_t xtrace_read;

static int xtrace_open(struct cdev *dev, int flag, int otyp, struct thread *td)
{
	int pid;

	pid = thrpid(td);

	if (!atomic_cmpset_int(&xtrace_opened, 0, 1))
	{
		printf("xtrace: open %d: failed : EBUSY\n", pid);
		return (EBUSY);
	}

	printf("xtrace: open: %d\n", pid);

	xtrace_pid_adds = 0;
	xtrace_pid_dels = 0;
	xtrace_msg_adds = 0;
	xtrace_msg_dels = 0;

	xtrace_add_pid(pid, "open");
	return (0);
}

static int xtrace_close(struct cdev *dev, int flag, int otyp, struct thread *td)
{
	int pid;
	TAILQ_HEAD(, xtrace_pid_entry)
	xtrace_pid_head_copy;
	TAILQ_HEAD(, xtrace_msg_entry)
	xtrace_msg_head_copy;
	struct xtrace_pid_entry *pitem;
	struct xtrace_msg_entry *mitem;
	int pf, mf;

	pid = thrpid(td);

	if (atomic_cmpset_int(&xtrace_opened, 1, 0) == 0)
	{
		printf("xtrace: close %d: failed\n", pid);
		return 0;
	}

	printf("xtrace: close %d\n", pid);

	// I don't want to free while lock held.
	TAILQ_INIT(&xtrace_pid_head_copy);
	mtx_lock(&xtrace_pid_mtx);
	while ((pitem = TAILQ_FIRST(&xtrace_pid_head)))
	{
		TAILQ_REMOVE(&xtrace_pid_head, pitem, entries);
		TAILQ_INSERT_TAIL(&xtrace_pid_head_copy, pitem, entries);
	}
	mtx_unlock(&xtrace_pid_mtx);

	pf = 0;
	while ((pitem = TAILQ_FIRST(&xtrace_pid_head_copy)))
	{
		TAILQ_REMOVE(&xtrace_pid_head_copy, pitem, entries);
		free(pitem, M_XTRACE_PID);
		pf += 1;
	}

	TAILQ_INIT(&xtrace_msg_head_copy);
	mtx_lock(&xtrace_msg_mtx);
	while ((mitem = TAILQ_FIRST(&xtrace_msg_head)))
	{
		TAILQ_REMOVE(&xtrace_msg_head, mitem, entries);
		TAILQ_INSERT_TAIL(&xtrace_msg_head_copy, mitem, entries);
	}
	mtx_unlock(&xtrace_msg_mtx);

	mf = 0;
	while ((mitem = TAILQ_FIRST(&xtrace_msg_head_copy)))
	{
		TAILQ_REMOVE(&xtrace_msg_head_copy, mitem, entries);
		free(mitem, M_XTRACE_MSG);
		mf += 1;
	}

	printf("xtrace: close %d: pid.{adds=%d, dels=%d}=%d "
		   "msg.{adds=%d, dels=%d}=%d\n",
		   pid,
		   xtrace_pid_adds, xtrace_pid_dels, pf,
		   xtrace_msg_adds, xtrace_msg_dels, mf);

	return (0);
}

static int xtrace_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int i, rv;
	size_t len, bytes;
	struct xtrace_msg_entry *item;

	// TODO: find user space, let uiomove do the job
	len = 0;
	for (i = 0; i < uio->uio_iovcnt; i += 1)
	{
		struct iovec *iov = &uio->uio_iov[i];
		len += iov->iov_len;
	}

	mtx_lock(&xtrace_msg_mtx);
	item = TAILQ_FIRST(&xtrace_msg_head);
	while (item == 0)
	{
		rv = mtx_sleep(&xtrace_msg_chan, &xtrace_msg_mtx, PCATCH, "xtrmsg", 0);
		if (rv == ERESTART)
		{
			mtx_unlock(&xtrace_msg_mtx);
			return ERESTART;
		}
		item = TAILQ_FIRST(&xtrace_msg_head);
	}
	bytes = item->msg.len + sizeof item->msg;
	if (bytes > len)
	{
		mtx_unlock(&xtrace_msg_mtx);
		return ERANGE;
	}
	TAILQ_REMOVE(&xtrace_msg_head, item, entries);
	mtx_unlock(&xtrace_msg_mtx);

	rv = uiomove(&item->msg, bytes, uio);
	free(item, M_XTRACE_MSG);

	return rv;
}

static struct cdevsw xtrace_sw = {
	/* version */ .d_version = D_VERSION,
	/* open */ .d_open = xtrace_open,
	/* close */ .d_close = xtrace_close,
	/* read */ .d_read = xtrace_read,
	/* name */ .d_name = "xtrace"};

MALLOC_DEFINE(M_XTRACE_BUF, "xtrbuf", "xtrace buffer");

static sy_call_t *cb_chdir = 0;
static int xtrace_chdir(struct thread *td, void *uap)
{
	char *buf;
	size_t len;
	int err;
	struct chdir_args *args;

	#ifdef _DEBUG
	printf("%5d: # chdir uap=%p\n", thrpid(td), uap);
	#endif

	args = (struct chdir_args *) uap;

	len = PATH_MAX;
	buf = (char *) malloc(len, M_XTRACE_BUF, M_NOWAIT);
	if (buf == 0) {
		printf("%5d: chdir: malloc failed\n", thrpid(td));
		return cb_chdir(td, uap);
	}

	err = copyinstr(args->path, buf, len, &len);
	if (err != 0) {
		printf("%5d: chdir: execinstr failed with %d\n", thrpid(td), err);
		free(buf, M_XTRACE_BUF);
		return cb_chdir(td, uap);
	}

	err = cb_chdir(td, uap);
	if (err > 0)
	{
		printf("%5d: chdir: failed with %d\n", thrpid(td), err);
		free(buf, M_XTRACE_BUF);
		return err;
	}

	xtrace_log(td, XTRACE_OP_CHDIR, 0, 0, 0, len, buf);

	free(buf, M_XTRACE_BUF);
	return err;
}

static sy_call_t *cb_execve = 0;
static int xtrace_execve(struct thread *td, void *uap)
{
	struct execve_args *args;
	char *buf, *ptr;
	void *tmpp, **tmpv;
	size_t len;
	size_t tmp;
	int argc, envc;
	#ifdef _DEBUG
	int i;
	#endif
	int err;

	#ifdef _DEBUG
	printf("%5d: # execve uap=%p\n", thrpid(td), uap);
	#endif

	args = (struct execve_args *) uap;
	
	len = PATH_MAX + ARG_MAX;
	buf = (char *) malloc(len, M_XTRACE_BUF, M_NOWAIT);
	if (buf == 0) {
		printf("%5d: execve: malloc failed\n", thrpid(td));
		return cb_execve(td, uap);
	}

	argc = envc = 0;
	ptr = buf;

	err = copyinstr(args->fname, ptr, len, &tmp);
	if (err != 0) {
		printf("%5d: execve: execinstr failed with %d\n", thrpid(td), err);
		free(buf, M_XTRACE_BUF);
		return cb_execve(td, uap);
	}
	
	tmpv = (void **) args->argv;
	for (;;) {
		ptr += tmp;
		len -= tmp;
		
		err = fueword(tmpv, (long *) &tmpp);
		if (err != 0) {
			break;
		}
		if (tmpp == 0) {
			break;
		}
		
		err = copyinstr(tmpp, ptr, len, &tmp);
		if (err != 0) {
			break;
		}
		
		argc += 1;
		tmpv += 1;
	}

	tmpv = (void **) args->envv;
	for (;;) {
		ptr += tmp;
		len -= tmp;
		
		err = fueword(tmpv, (long *) &tmpp);
		if (err != 0) {
			break;
		}
		if (tmpp == 0) {
			break;
		}
		
		err = copyinstr(tmpp, ptr, len, &tmp);
		if (err != 0) {
			break;
		}
		
		envc += 1;
		tmpv += 1;
	}

	err = cb_execve(td, uap);
	if (err > 0)
	{
		printf("%5d: # execve failed with %d\n", thrpid(td), err);
		free(buf, M_XTRACE_BUF);
		return err;
	}

	ptr += tmp;
	xtrace_log(td, XTRACE_OP_EXEC, argc, envc, 0, ptr - buf, buf);
	
	#ifdef _DEBUG
	ptr = buf;
	printf("%5d: execve -> %s\n", thrpid(td), ptr);

	if (argc > 0) {
		printf("args:\n");
	}
	for (i = 0; i < argc; i += 1) {
		ptr += strlen(ptr) + 1;
		printf("\t%2d: %s\n", i, ptr);
	}

	if (envc > 0) {
		printf("envs:\n");
	}
	for (i = 0; i < envc; i += 1) {
		ptr += strlen(ptr) + 1;
		printf("\t%2d: %s\n", i, ptr);
	}
	#endif

	free(buf, M_XTRACE_BUF);
	return err;
}

static sy_call_t *cb_fork = 0;
static int xtrace_fork(struct thread *td, void *uap)
{
	int ppid, pid, err;

	#ifdef _DEBUG
	printf("%5d: # fork\n", thrpid(td));
	#endif

	err = cb_fork(td, uap);
	if (err <= 0)
	{
		ppid = thrpid(td);

		pid = (int)td->td_retval[0];
		xtrace_log(td, XTRACE_OP_FORK, pid, 0, 0, 0, 0);

		#ifdef _DEBUG
		printf("%5d: fork -> %d\n", ppid, pid);
		#endif
	}
	else
	{
		printf("%5d: # fork failed with %d\n", thrpid(td), err);
	}

	return err;
}

static sy_call_t *cb_vfork = 0;
static int xtrace_vfork(struct thread *td, void *uap)
{
	int ppid, pid, err;

	#ifdef _DEBUG
	printf("%5d: # vfork\n", thrpid(td));
	#endif

	err = cb_vfork(td, uap);
	if (err <= 0)
	{
		ppid = thrpid(td);

		pid = (int)td->td_retval[0];
		xtrace_log(td, XTRACE_OP_FORK, pid, 0, 0, 0, 0);

		#ifdef _DEBUG
		printf("%5d: vfork -> %d\n", ppid, pid);
		#endif
	}
	else
	{
		printf("%5d: # vfork failed with %d\n", thrpid(td), err);
	}

	return err;
}

static sy_call_t *cb_exit = 0;
static int xtrace_exit(struct thread *td, void *uap)
{
	struct sys_exit_args *args;

	#ifdef _DEBUG
	printf("%5d: # exit\n", thrpid(td));
	#endif

	args = (struct sys_exit_args *)uap;
	xtrace_log(td, XTRACE_OP_EXIT, args->rval, 0, 0, 0, 0);

	// should not return
	return cb_exit(td, uap);
}

static struct cdev *sdev;

static void xtrace_init(void *arg)
{
	printf("xtrace: init\n");

	// hook fork
	cb_fork = sysent[SYS_fork].sy_call;
	sysent[SYS_fork].sy_call = &xtrace_fork;

	// hook vfork
	cb_vfork = sysent[SYS_vfork].sy_call;
	sysent[SYS_vfork].sy_call = &xtrace_vfork;

	// hook exit
	cb_exit = sysent[SYS_exit].sy_call;
	sysent[SYS_exit].sy_call = &xtrace_exit;

	// hook execve
	cb_execve = sysent[SYS_execve].sy_call;
	sysent[SYS_execve].sy_call = &xtrace_execve;

	// hook chdir
	cb_chdir = sysent[SYS_chdir].sy_call;
	sysent[SYS_chdir].sy_call = &xtrace_chdir;

	sdev = make_dev(&xtrace_sw, 0, UID_ROOT, GID_WHEEL, 0600, "xtrace");
}

static void xtrace_uninit(void *arg)
{
	printf("xtrace: uninit\n");

	sysent[SYS_execve].sy_call = cb_execve;
	sysent[SYS_exit].sy_call = cb_exit;
	sysent[SYS_fork].sy_call = cb_fork;
	sysent[SYS_vfork].sy_call = cb_vfork;
	sysent[SYS_chdir].sy_call = cb_chdir;

	destroy_dev(sdev);
}

SYSINIT(xtrace, SI_SUB_DRIVERS, SI_ORDER_ANY, xtrace_init, NULL);
SYSUNINIT(xtrace, SI_SUB_DRIVERS, SI_ORDER_ANY, xtrace_uninit, NULL);
