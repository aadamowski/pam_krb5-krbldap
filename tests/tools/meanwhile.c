/*
 * Copyright 2011 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
 *
 */

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	pid_t *children;
	int n_children, i, mul, sig, status, ret, verbose = 0;
	char *cmd, *args[4], **cmds, **execs;
	signal(SIGCHLD, SIG_DFL);
	if (argc < 2) {
		return -1;
	}
	/* Parse command line arguments and count the number of commands we'll
	 * launch as "background" processes. */
	for (i = 1, n_children = 0; i < argc - 1; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose++;
		}
		n_children++;
	}
	/* Make some room. */
	cmds = malloc(sizeof(char *) * (n_children + 1));
	if (cmds == NULL) {
		perror("malloc");
		return -1;
	}
	execs = malloc(sizeof(char *) * (n_children + 1));
	if (execs == NULL) {
		perror("malloc");
		return -1;
	}
	children = malloc(sizeof(pid_t) * n_children);
	if (children == NULL) {
		perror("malloc");
		return -1;
	}
	/* Capture each "background" command, the command we'll run in the
	 * foreground, and the variant we'll use to make the shell do the
	 * parsing and piping. */
	cmd = argv[argc - 1];
	for (i = 1, n_children = 0; i < argc - 1; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose++;
			continue;
		}
		cmds[n_children] = argv[i];
		execs[n_children] = malloc(5 + strlen(argv[i]) + 1);
		if (execs[n_children] == NULL) {
			perror("malloc");
			return -1;
		}
		sprintf(execs[n_children], "exec %s", cmds[n_children]);
		children[n_children] = -1;
		n_children++;
	}
	/* Walk the list of "background" children and start them up. */
	for (i = 0; i < n_children; i++) {
		args[0] = _PATH_BSHELL;
		args[1] = "-c";
		args[2] = execs[i];
		args[3] = NULL;
		children[i] = fork();
		switch (children[i]) {
		case -1:
			/* Failure launching.  Keep going. */
			memcpy(execs[i], "fork", 4);
			perror(execs[i]);
			break;
		case 0:
			/* Child.  Exec the actual command with the shell's
			 * help. */
			if (verbose) {
				fprintf(stderr, "[%ld] %s\n", (long) getpid(),
					execs[i]);
			}
			execvp(args[0], args);
			return -1;
		default:
			/* Parent. */
			break;
		}
	}
	/* Run the foreground command. */
	if (verbose) {
		fprintf(stderr, "[%ld] %s\n", (long) getpid(), cmd);
	}
	ret = system(cmd);
	if (verbose) {
		fprintf(stderr, "[%ld] result is %d\n", (long) getpid(), ret);
	}
	/* Clean up the background processes. */
	for (i = 0; i < n_children; i++) {
		if (children[i] == -1) {
			continue;
		}
		status = 0;
		mul = 1;
		sig = SIGTERM;
		while (waitpid(children[i], &status, WNOHANG) != children[i]) {
			if (verbose) {
				fprintf(stderr, "[%ld] kill -%s %ld\n",
					(long) getpid(), strsignal(sig),
					(long) children[i]);
			}
			kill(children[i], sig);
			usleep(mul++ * 100000);
			if (mul > 20) {
				sig = SIGKILL;
			}
		}
		if (verbose) {
			printf("Process %ld (%s) stopped.\n",
			       (long) children[i], cmds[i]);
		}
	}
	return ret;
}
