/*
 * Copyright (c) 2015-2018 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2015-2023 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	const off_t offset = (off_t) 0xfacefeeddeadbeefULL;

	off_t rc = lseek(-1L, offset, SEEK_SET);
	printf("lseek(-1, %ld, SEEK_SET) = %ld EBADF (bad file descriptor)\n", (long) offset, (long) rc);

	puts("+++ exited with 0 +++");
	return 0;
}
