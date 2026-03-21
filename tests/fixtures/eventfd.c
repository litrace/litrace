/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main(void)
{
	long fd = syscall(SYS_eventfd, 7U);
	if (fd < 0) {
		perror("eventfd");
		return 1;
	}

	printf("eventfd(%u) = %ld\n", 7U, fd);

	if (close((int) fd) != 0) {
		perror("close");
		return 1;
	}

	puts("+++ exited with 0 +++");
	return 0;
}
