/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
	char dir[PATH_MAX];
	char match[PATH_MAX];
	char seed[PATH_MAX];
	struct stat st;
	int dirfd;

	if (snprintf(dir, sizeof(dir), "/tmp/litrace_path_filter_newfstatat") >= (int) sizeof(dir))
		fail("snprintf dir");
	if (snprintf(match, sizeof(match), "%s/target.tmp", dir) >= (int) sizeof(match))
		fail("snprintf match");
	if (snprintf(seed, sizeof(seed), "%s/target.seed.tmp", dir) >= (int) sizeof(seed))
		fail("snprintf seed");

	(void) unlink(match);
	(void) unlink(seed);
	(void) rmdir(dir);

	if (mkdir(dir, 0700) && errno != EEXIST)
		fail("mkdir dir");

	dirfd = open(seed, O_CREAT | O_RDONLY, 0600);
	if (dirfd == -1)
		fail("create seed");
	if (close(dirfd))
		fail("close create seed");
	if (rename(seed, match))
		fail("rename seed");

	dirfd = open(dir, O_RDONLY | O_DIRECTORY);
	if (dirfd == -1)
		fail("open dir");

	if (syscall(SYS_newfstatat, dirfd, "target.tmp", &st, 0))
		fail("newfstatat target");
	printf("newfstatat(%d, \"target.tmp\", %p, 0) = 0\n", dirfd, (void *) &st);

	if (close(dirfd))
		fail("close dir");
	if (unlink(match))
		fail("unlink match");
	(void) unlink(seed);
	if (rmdir(dir))
		fail("rmdir dir");

	puts("+++ exited with 0 +++");
	return 0;
}
