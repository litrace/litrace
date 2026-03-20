/*
 * Check decoding of fchmod syscall.
 *
 * Copyright (c) 2016 Fabien Siron <fabien.siron@epita.fr>
 * Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2016-2022 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
fail(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

int
main(void)
{
	static const char sample[] = "fchmod_sample_file";
	(void) unlink(sample);
	int fd = open(sample, O_CREAT|O_RDONLY, 0400);
	if (fd == -1)
		fail("open sample");

	static const char sample_del[] = "fchmod_sample_file (deleted)";
	(void) unlink(sample_del);
	int fd_del = open(sample_del, O_CREAT|O_RDONLY, 0400);
	if (fd_del == -1)
		fail("open deleted sample");

	int rc = fchmod(fd, 0600);
	if (rc == -1)
		fail("fchmod sample 0600");
	printf("fchmod(%d, 0600) = %d\n", fd, rc);

	rc = fchmod(fd_del, 0600);
	if (rc == -1)
		fail("fchmod deleted sample 0600");
	printf("fchmod(%d, 0600) = %d\n", fd_del, rc);

	if (unlink(sample))
		fail("unlink sample");

	rc = fchmod(fd, 051);
	if (rc == -1)
		fail("fchmod unlinked sample 051");
	printf("fchmod(%d, 051) = %d\n", fd, rc);

	if (unlink(sample_del))
		fail("unlink deleted sample");

	rc = fchmod(fd_del, 051);
	if (rc == -1)
		fail("fchmod unlinked deleted sample 051");
	printf("fchmod(%d, 051) = %d\n", fd_del, rc);

	rc = fchmod(fd, 004);
	if (rc == -1)
		fail("fchmod unlinked sample 004");
	printf("fchmod(%d, 004) = %d\n", fd, rc);

	if (close(fd))
		fail("close sample");
	if (close(fd_del))
		fail("close deleted sample");

	puts("+++ exited with 0 +++");
	return 0;
}
