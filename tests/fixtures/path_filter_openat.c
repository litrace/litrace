/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

	if (snprintf(match, sizeof(match), "/tmp/litrace_path_filter_match.tmp") >= (int) sizeof(match))
		fail("snprintf match");
	if (snprintf(other, sizeof(other), "/tmp/litrace_path_filter_other.tmp") >= (int) sizeof(other))
		fail("snprintf other");
	if (snprintf(match_seed, sizeof(match_seed), "/tmp/litrace_path_filter_match_seed.tmp") >= (int) sizeof(match_seed))
		fail("snprintf match_seed");
	if (snprintf(other_seed, sizeof(other_seed), "/tmp/litrace_path_filter_other_seed.tmp") >= (int) sizeof(other_seed))
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

	fd = openat(AT_FDCWD, match, O_RDONLY);
	if (fd == -1)
		fail("openat match");
	printf("openat(AT_FDCWD, \"%s\", O_RDONLY) = %d\n", match, fd);
	if (close(fd))
		fail("close match");

	fd = openat(AT_FDCWD, other, O_RDONLY);
	if (fd == -1)
		fail("openat other");
	if (close(fd))
		fail("close other");

	if (unlink(match))
		fail("unlink match");
	if (unlink(other))
		fail("unlink other");

	puts("+++ exited with 0 +++");
	return 0;
}
