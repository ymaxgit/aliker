/*
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Li Yu :		Starting up.
 */

#ifndef _LINUX_HOOKER_H_
#define _LINUX_HOOKER_H_

#include <linux/types.h>

struct hooked_place;

/*
 * This API allows us replace and restore the function pointer in any order.
 *
 * This is designed to satisfy hooker stack usage pattern. e.g.
 *
 *	In our TCP implemention, icsk_af_ops->syn_recv_sock is called
 *	when thea three way handshake has completed, we need to hook it
 *      sometimes, e.g. to compute some statistics data on fly, even to
 *      add a private TCP option.
 *
 *  By hooking this function, we can attain the goal without any kernel
 *  change or just some small changes, and hope that this can help to
 *  reduce the cost of maintaining custom kernel release too. Of course,
 *  this can't replace that design necessary extendible framework, but I
 *  think that hooking is a good and cheep choice of starting all.
 *
 *	Assume that we have two hooks, we expect that the hooking could
 *      produce below behavior:
 *
 *	First, install two hookers:
 *
 *          install(&syn_recv_sock, hook1)
 *          install(&syn_recv_sock, hook2)
 *
 *	Now, we expect the invoking order is:
 *
 *	     orig_syn_recv_sock() , hook2() , hook1()
 *
 *	Then, remove a hooker:
 *
 *          uninstall(&syn_recv_sock, hook1)
 *
 *      Then, the invoking order should be:
 *
 *	   orig_syn_recv_sock(), hook2()
 *
 *	Last, remove all rest hookers:
 *
 *          uninstall(&syn_recv_sock, hook2)
 *
 *      The result just is:
 *
 *	    orig_syn_recv_sock()
 *
 *      See, it is function pointer stack here. however, if we just simplely
 *	used address of hooker1 in "top" hooker function (hooker2),
 *	we will get an invalid memory access exception when prior hookers
 *      (hooker1) is uninstalled first. Under second simple design, we just
 *      support the some fixed predefined hooking addresses, and manage hookers
 *      by a simple linked list.
 *
 *
 * Usage:
 *
 *	1. Install a hooker on address which you are interesting in.
 *	   Assume that the kernel has a callback table as below:
 *
 *		struct icsk_ops {
 *			...
			 *int (*foo)(int a, char b);
 *			...
 *		};
 *
 *		struct icsk_ops icsk_ops = {
 *			...
 *			.foo = real_foo,
 *			...
 *		};
 *
 *	   Then we should hook &icsk_ops.foo by such way:
 *
 *		static int foo_hooker(int a, char b, int *p_ret)
 *		{
 *			int ret = *p_ret;
 *
 *			//do something that may overwrite return value.
 *			//p_ret saves the result value of original function
 *			//or other hookers.
 *
 *			//You should not have any assume for invoking order
 *			//of hookers.
 *
 *			return ret;
 *		}
 *
 *		struct hooker h = {
 *			.func = foo_hooker,
 *		};
 *
 *		hooker_install(&icsk_ops.foo ,&h);
 *
 *		The hooker and original function has same function signature, if
 *		the original function has not return value, IOW, it's like
 *
 *			void foo(int a, char b) { ... }
 *
 *	2. Uninstall hooker is easy, just:
 *
 *		hooker_uninstall(&h);
 *
 */

struct hooker {
	struct hooked_place *hplace;
	void *func;	/* the installed hooker function pointer */
	struct list_head chain;
};

/*
 * Install the hooker function at specified address.
 * This function may sleep.
 *
 * Parameters:
 *	place - the address that saves function pointer
 *	hooker - the hooker to install, the caller must fill
 *		 its func member first
 *
 * Return:
 *	    0  - All OK, please note that hooker func may be called before
 *		 this return
 *	  < 0 -  any error, e.g. out of memory, existing same installed hooker
 */
extern int hooker_install(void *place, struct hooker *hooker);

/*
 * Remove the installed hooker function that saved in hooker->func.
 * This function may sleep.
 *
 * Parameters:
 *	place - the address that saves function pointer
 *	hooker - the installed hooker struct
 */
extern void hooker_uninstall(struct hooker *hooker);

#endif
