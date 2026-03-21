/*
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
	static const char sample[] = "fstat_sample_file";
	static const char payload[] = "hello\n";
	struct stat st;
	int fd;

	(void) unlink(sample);
	(void) umask(0);

	fd = open(sample, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd == -1)
		fail("open sample");

	if (write(fd, payload, sizeof(payload) - 1) != (ssize_t) (sizeof(payload) - 1))
		fail("write sample");
	if (fstat(fd, &st))
		fail("fstat sample");

	printf("fstat(%d, {st_mode=S_IFREG|0644, st_size=%lld, ...}) = 0\n",
	       fd, (long long) st.st_size);

	if (close(fd))
		fail("close sample");
	if (unlink(sample))
		fail("unlink sample");

	puts("+++ exited with 0 +++");
	return 0;
}
