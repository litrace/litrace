/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int
main(void)
{
	char ch;
	int i;

	umask(022);

	if (read(STDIN_FILENO, &ch, 1) != 1)
		return 2;

	for (i = 0; i < 100; i++) {
		mode_t rc = umask(0);
		printf("umask(%#03ho) = %#03o\n", (unsigned short) 0, rc);
		umask(022);
		usleep(10000);
	}
	return 0;
}
