/*
 * Minimal strace-style fixture helpers for litrace tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LITRACE_FIXTURES_TESTS_H
#define LITRACE_FIXTURES_TESTS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LENGTH_OF(a) (sizeof(a) - 1)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef unsigned long long kernel_ulong_t;

static FILE *litrace_fixture_output_stream;

static inline void
litrace_fixture_init_output(void)
{
	int saved_stdout = dup(STDOUT_FILENO);

	if (saved_stdout < 0) {
		perror("dup stdout");
		exit(1);
	}
	litrace_fixture_output_stream = fdopen(saved_stdout, "w");
	if (!litrace_fixture_output_stream) {
		perror("fdopen stdout");
		close(saved_stdout);
		exit(1);
	}
}

static inline void
litrace_fixture_reserve_stdio_fds(void)
{
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);
}

static inline void
litrace_fixture_flush_output(void)
{
	if (litrace_fixture_output_stream)
		fflush(litrace_fixture_output_stream);
}

static inline void
litrace_fixture_close_output(void)
{
	if (litrace_fixture_output_stream) {
		fflush(litrace_fixture_output_stream);
		fclose(litrace_fixture_output_stream);
		litrace_fixture_output_stream = NULL;
	}
}

static inline void
tprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(litrace_fixture_output_stream, fmt, ap);
	va_end(ap);
}

static inline void
perror_msg_and_fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	litrace_fixture_flush_output();
	exit(1);
}

#endif
