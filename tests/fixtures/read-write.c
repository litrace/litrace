/*
 * Check decoding and dumping of read and write syscalls.
 *
 * Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2016-2023 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tests.h"

#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static long
k_read(unsigned int fd, void *buf, size_t count)
{
	kernel_ulong_t kfd = (kernel_ulong_t) 0xfacefeed00000000ULL | fd;

	return syscall(__NR_read, kfd, buf, count);
}

static long
k_write(unsigned int fd, const void *buf, size_t count)
{
	kernel_ulong_t kfd = (kernel_ulong_t) 0xfacefeed00000000ULL | fd;

	return syscall(__NR_write, kfd, buf, count);
}

int
main(void)
{
	static const char tmp[] = "/tmp/litrace-read-write.sample";
	static const char w_c[] = "0123456789abcde";
	static const unsigned int w_len = LENGTH_OF(w_c);
	static const char r0_c[] = "01234567";
	static const unsigned int r0_len = (w_len + 1) / 2;
	static const char r1_c[] = "89abcde";
	static const unsigned int r1_len = w_len - r0_len;
	bool need_cleanup = true;
	int in_fd;
	int out_fd;
	const char *w = w_c;
	char r0_c_buf[r0_len];
	char r1_buf[w_len];
	void *r0 = r0_c_buf;
	void *r1 = r1_buf;
	long rc;

	litrace_fixture_init_output();

	tprintf("%s", "");

	(void) unlink(tmp);
	litrace_fixture_reserve_stdio_fds();

	rc = open(tmp, O_RDONLY, 0600);
	if (rc < 0) {
		rc = open(tmp, O_CREAT | O_EXCL | O_RDONLY, 0600);
		need_cleanup = false;
	}
	if (rc != 0)
		perror_msg_and_fail("creat: %s", tmp);
	in_fd = (int) rc;

	rc = open(tmp, O_TRUNC | O_WRONLY);
	if (rc != 1)
		perror_msg_and_fail("open: %s", tmp);
	out_fd = (int) rc;

	rc = k_write(out_fd, w, 0);
	if (rc != 0) {
		perror_msg_and_fail("write: expected 0, returned %ld", rc);
	}
	tprintf("write(%d, \"\", 0) = 0\n", out_fd);

	rc = k_write(out_fd, w, w_len);
	if (rc != (long) w_len) {
		perror_msg_and_fail("write: expected %u, returned %ld", w_len, rc);
	}
	tprintf("write(%d, \"%s\", %u) = %ld\n", out_fd, w_c, w_len, rc);

	close(out_fd);

	rc = k_read(in_fd, r0, 0);
	if (rc != 0) {
		perror_msg_and_fail("read: expected 0, returned %ld", rc);
	}
	tprintf("read(%d, \"\", 0) = 0\n", in_fd);

	rc = k_read(in_fd, r0, r0_len);
	if (rc != (long) r0_len) {
		perror_msg_and_fail("read: expected %u, returned %ld", r0_len, rc);
	}
	if (memcmp(r0, r0_c, r0_len) != 0) {
		perror_msg_and_fail("read payload mismatch");
	}
	tprintf("read(%d, \"%s\", %u) = %ld\n", in_fd, r0_c, r0_len, rc);

	rc = k_read(in_fd, r1, w_len);
	if (rc != (long) r1_len) {
		perror_msg_and_fail("read: expected %u, returned %ld", r1_len, rc);
	}
	if (memcmp(r1, r1_c, r1_len) != 0) {
		perror_msg_and_fail("read payload mismatch");
	}
	tprintf("read(%d, \"%s\", %u) = %ld\n", in_fd, r1_c, w_len, rc);

	close(in_fd);
	if (need_cleanup && unlink(tmp))
		perror_msg_and_fail("unlink: %s", tmp);

	tprintf("+++ exited with 0 +++\n");
	litrace_fixture_close_output();
	return 0;
}
