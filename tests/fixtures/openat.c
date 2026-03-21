/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main(void)
{
	const char sample[] = "openat.sample";

	(void) unlink(sample);

	long fd = syscall(SYS_openat, AT_FDCWD, sample, O_RDONLY | O_CREAT, 0400);
	if (fd < 0) {
		perror("openat create");
		return 1;
	}

	printf("openat(AT_FDCWD, \"%s\", O_RDONLY|O_CREAT, 0400) = %ld\n", sample, fd);

	if (close((int) fd) != 0) {
		perror("close create");
		return 1;
	}

	fd = syscall(SYS_openat, AT_FDCWD, sample, O_RDONLY);
	if (fd < 0) {
		perror("openat readonly");
		return 1;
	}

	printf("openat(AT_FDCWD, \"%s\", O_RDONLY) = %ld\n", sample, fd);

	if (close((int) fd) != 0) {
		perror("close readonly");
		return 1;
	}

	if (unlink(sample) != 0) {
		perror("unlink");
		return 1;
	}

	puts("+++ exited with 0 +++");
	return 0;
}
