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
	int dirfd;
	int fd;

	if (snprintf(dir, sizeof(dir), "/tmp/litrace_path_filter_dirfd") >= (int) sizeof(dir))
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

	fd = open(seed, O_CREAT | O_RDONLY, 0600);
	if (fd == -1)
		fail("create seed");
	if (close(fd))
		fail("close create seed");
	if (rename(seed, match))
		fail("rename seed");

	dirfd = open(dir, O_RDONLY | O_DIRECTORY);
	if (dirfd == -1)
		fail("open dir");

	fd = syscall(SYS_openat, dirfd, "target.tmp", O_RDONLY);
	if (fd == -1)
		fail("openat match");
	printf("openat(%d, \"target.tmp\", O_RDONLY) = %d\n", dirfd, fd);

	if (close(fd))
		fail("close match");
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
