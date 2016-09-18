# x-trace
FreeBSD 11 kernel hacking example : x-trace, simple tool to trace execution

Description
--------------

This is a simple example of FreeBSD 11 kernel hacking. It comes with a driver (sys/), a userland program that communicates with the driver (bin/xtrace) and two tools (bin/xdump, bin/xdot) to dump the content of the binary file created by xtrace.

How to install
--------------

	# git clone https://github.com/xigh/x-trace
	# cd x-trace
	# make

How to use it
--------------

	# kldload sys/xtrace.ko

	# bin/xtrace/xtrace /bin/ls
	started pid 4467
	Makefile	bin		sys		xtrace.out
	child returned with 0

	# bin/xdump/xdump xtrace.out 
	 4466: fork pid=4467
	  4467: exec '/bin/ls' argc=1 envc=24
		argv:
		   0: /bin/ls
		envv:
		   0: e
		   1: bin/xtSHELL=/bin/csh
		   2: SSH_CLIENT=2a01:....
		   3: LOGNAME=xigh
		   4: PAGER=more
		   5: MAIL=/var/mail/xigh
		   6: PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:...
		   7: EDITOR=vi
		   8: ENV=/home/xigh/.shrc
		   9: OLDPWD=/usr/home/xigh/src
		  10: PWD=/usr/home/xigh/src/xtrace
		  11: TERM=xterm-256color
		  12: SSH_TTY=/dev/pts/1
		  13: HOME=/root
		  14: USER=xigh
		  15: SSH_CONNECTION=2a01:....
		  16: BLOCKSIZE=K
		  17: HOSTTYPE=FreeBSD
		  18: VENDOR=amd
		  19: OSTYPE=FreeBSD
		  20: MACHTYPE=x86_64
		  21: SHLVL=1
		  22: GROUP=wheel
		  23: HOST=fbsd11
	 4467: exit rval=0

How it works
--------------

When the kernel module loads, it install hooks on a few syscalls:

	cb_fork = sysent[SYS_fork].sy_call;
	sysent[SYS_fork].sy_call =  &xtrace_fork;
	cb_vfork = sysent[SYS_vfork].sy_call;
	sysent[SYS_vfork].sy_call =  &xtrace_vfork;
	cb_exit = sysent[SYS_exit].sy_call;
	sysent[SYS_exit].sy_call =  &xtrace_exit;
	cb_exec = sysent[SYS_execve].sy_call;
	sysent[SYS_execve].sy_call =  &xtrace_exec;


	static sy_call_t *cb_exit = 0;
	static int xtrace_exit(struct thread *td, void *uap) {
	       return cb_exit(td, uap);
	}

Licence
--------------

   Copyright (c) 2013-2016 Philippe Anel. All rights reserved.
  
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   4. Neither the name of the University nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.
  
   THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.
