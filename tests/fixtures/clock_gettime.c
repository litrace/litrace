/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int
main(void)
{
	struct timespec ts = { 0 };
	long rc = syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts);

	printf("clock_gettime(%d, 0x%lx) = %ld\n",
	       CLOCK_REALTIME,
	       (unsigned long) (uintptr_t) &ts,
	       rc);
	puts("+++ exited with 0 +++");
	return 0;
}
