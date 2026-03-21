/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
	static const char sample[] = "stat.sample";
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
	if (close(fd))
		fail("close sample");

	if (syscall(SYS_stat, sample, &st))
		fail("stat sample");
	printf("stat(\"%s\", {st_mode=S_IFREG|0644, st_size=%lld, ...}) = 0\n",
	       sample, (long long) st.st_size);

	if (unlink(sample))
		fail("unlink sample");

	puts("+++ exited with 0 +++");
	return 0;
}
