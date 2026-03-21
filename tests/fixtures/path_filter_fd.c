/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	char match[PATH_MAX];
	char other[PATH_MAX];
	char match_seed[PATH_MAX];
	char other_seed[PATH_MAX];
	int fd;
	int dupfd;

	if (snprintf(match, sizeof(match), "/tmp/litrace_path_filter_fd_match.tmp") >= (int) sizeof(match))
		fail("snprintf match");
	if (snprintf(other, sizeof(other), "/tmp/litrace_path_filter_fd_other.tmp") >= (int) sizeof(other))
		fail("snprintf other");
	if (snprintf(match_seed, sizeof(match_seed), "/tmp/litrace_path_filter_fd_match_seed.tmp") >= (int) sizeof(match_seed))
		fail("snprintf match_seed");
	if (snprintf(other_seed, sizeof(other_seed), "/tmp/litrace_path_filter_fd_other_seed.tmp") >= (int) sizeof(other_seed))
		fail("snprintf other_seed");

	(void) unlink(match);
	(void) unlink(other);
	(void) unlink(match_seed);
	(void) unlink(other_seed);

	fd = open(match_seed, O_CREAT | O_RDONLY, 0600);
	if (fd == -1)
		fail("create match");
	if (close(fd))
		fail("close create match");
	if (rename(match_seed, match))
		fail("rename match");

	fd = open(other_seed, O_CREAT | O_RDONLY, 0600);
	if (fd == -1)
		fail("create other");
	if (close(fd))
		fail("close create other");
	if (rename(other_seed, other))
		fail("rename other");

	fd = syscall(SYS_openat, AT_FDCWD, match, O_RDONLY);
	if (fd == -1)
		fail("open match");
	printf("openat(AT_FDCWD, \"%s\", O_RDONLY) = %d\n", match, fd);

	if (lseek(fd, 0, SEEK_SET) == -1)
		fail("lseek match");
	printf("lseek(%d, 0, SEEK_SET) = 0\n", fd);

	dupfd = syscall(SYS_dup, fd);
	if (dupfd == -1)
		fail("dup match");
	printf("dup(%d) = %d\n", fd, dupfd);

	if (close(dupfd))
		fail("close dup match");
	printf("close(%d) = 0\n", dupfd);

	if (close(fd))
		fail("close match");
	printf("close(%d) = 0\n", fd);

	fd = syscall(SYS_openat, AT_FDCWD, other, O_RDONLY);
	if (fd == -1)
		fail("open other");
	if (lseek(fd, 0, SEEK_SET) == -1)
		fail("lseek other");
	if (close(fd))
		fail("close other");

	if (unlink(match))
		fail("unlink match");
	if (unlink(other))
		fail("unlink other");

	puts("+++ exited with 0 +++");
	return 0;
}
