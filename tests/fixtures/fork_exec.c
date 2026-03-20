/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int
main(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		char *const argv[] = { "true", NULL };
		execve("/bin/true", argv, environ);
		perror("execve");
		_exit(127);
	}

	printf("%ld\n", (long) pid);
	fflush(stdout);

	if (waitpid(pid, NULL, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	return 0;
}
