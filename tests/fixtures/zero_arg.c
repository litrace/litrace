/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
	printf("getpid() = %ld\n", (long) getpid());
	printf("getppid() = %ld\n", (long) getppid());
	printf("getuid() = %ld\n", (long) getuid());
	printf("getgid() = %ld\n", (long) getgid());
	printf("sched_yield() = %d\n", sched_yield());

	puts("+++ exited with 0 +++");
	return 0;
}
