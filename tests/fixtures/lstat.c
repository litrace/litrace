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
	static const char target[] = "lstat.target";
	static const char linkname[] = "lstat.sample";
	struct stat st;
	int fd;

	(void) unlink(linkname);
	(void) unlink(target);

	fd = open(target, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd == -1)
		fail("open target");
	if (close(fd))
		fail("close target");
	if (symlink(target, linkname))
		fail("symlink sample");

	if (syscall(SYS_lstat, linkname, &st))
		fail("lstat sample");
	printf("lstat(\"%s\", {st_mode=S_IFLNK|0777, st_size=%lld, ...}) = 0\n",
	       linkname, (long long) st.st_size);

	if (unlink(linkname))
		fail("unlink link");
	if (unlink(target))
		fail("unlink target");

	puts("+++ exited with 0 +++");
	return 0;
}
