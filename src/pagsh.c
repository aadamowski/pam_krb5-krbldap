/*
 * Copyright 2004,2005 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <krb5.h>
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include <security/pam_appl.h>

#include "logstdio.h"
#include "options.h"
#include "stash.h"
#include "minikafs.h"
#include "xstr.h"

struct _pam_krb5_options;
extern char *log_progname;

int
main(int argc, char **argv)
{
	const char *shell;
	char **new_argv;
	int i;

	memset(&log_options, 0, sizeof(log_options));
	log_progname = "pagsh";
	shell = getenv("SHELL");
	if ((shell == NULL) || (strlen(shell) == 0)) {
		shell = _PATH_BSHELL;
	}
	new_argv = malloc(sizeof(char*) * argc);
	if (new_argv == NULL) {
		fprintf(stderr, "pagsh: out of memory\n");
		return 1;
	}
	for (i = 0; i < argc; i++) {
		switch (i) {
		case 0:
			new_argv[i] = xstrdup(shell);
			break;
		case 1:
			if (argv[i][0] == '-') {
				fprintf(stdout,
					"Usage: pagsh [command [args ...]]\n");
				return 1;
			}
		default:
			new_argv[i] = xstrdup(argv[i]);
			break;
		}
	}
	if (minikafs_has_afs()) {
		if (minikafs_setpag() != 0) {
			fprintf(stderr, "pagsh: error creating new PAG\n");
		}
	}
	execvp(new_argv[0], new_argv);
	fprintf(stderr, "pagsh: exec() failed: %s\n", strerror(errno));
	return 1;
}
