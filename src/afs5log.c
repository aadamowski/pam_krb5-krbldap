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
#include <limits.h>
#include <stdarg.h>
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

#ident "$Id$"

extern char *log_progname;

int
main(int argc, char **argv)
{
	char local[PATH_MAX], home[PATH_MAX], path[PATH_MAX];
	char *homedir, *cell, *principal, *pathdir;
	int i, j, try_v5_2b, cells;
	krb5_context ctx;
	krb5_ccache ccache;
	uid_t uid;

	/* Iterate through every parameter, assuming they're names of cells. */
#ifdef USE_KRB4
	try_v5_2b = 0;
#else
	try_v5_2b = 1;
#endif
	cells = 0;
	log_progname = "afs5log";
	uid = getuid();
	memset(&log_options, 0, sizeof(log_options));
	memset(&ccache, 0, sizeof(ccache));
	i = krb5_init_context(&ctx);
	if (i != 0) {
		fprintf(stderr, "Error initializing Kerberos: %d\n", i);
		exit(1);
	}
	i = krb5_cc_default(ctx, &ccache);
	if (i != 0) {
		fprintf(stderr, "Error reading default credential cache: %d\n",
			i);
		exit(1);
	}
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'v':
				log_options.debug++;
				break;
			default:
				break;
			}
		}
	}
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case '5':
				try_v5_2b = !try_v5_2b;
				break;
			case 'v':
				break;
			case 'p':
				i++;
				pathdir = argv[i];
				j = minikafs_cell_of_file_walk_up(pathdir, path,
								  sizeof(path));
				if ((j == 0) &&
				    (strcmp(path, "dynroot") != 0) &&
				    (strcmp(path, local) != 0)) {
					if (log_options.debug) {
						debug("cell of \"%s\" is "
						      "\"%s\"", pathdir, path);
					}
					j = minikafs_log(NULL, ccache,
							 &log_options,
							 path, NULL,
							 uid, try_v5_2b);
					if (j != 0) {
						fprintf(stderr,
							"%s: %d\n", path, j);
					}
				}
				break;
			default:
				printf("%s: [ [-v] [-5] [-p path] "
				       "[cell[=principal]] ] [...]\n", argv[0]);
				krb5_free_context(ctx);
				exit(0);
				break;
			}
		} else {
			cells++;
			cell = xstrdup(argv[i]);
			principal = strchr(cell, '=');
			if (principal != NULL) {
				*principal = '\0';
				principal++;
			}
			j = minikafs_log(NULL, ccache, &log_options,
					 cell, principal, uid, try_v5_2b);
			if (j != 0) {
				fprintf(stderr, "%s: %d\n", argv[i], j);
			}
			xstrfree(cell);
		}
	}

	/* If no parameters were offered, go for the user's home directory and
	 * the local cell, if we can determine what its name is. */
	if (cells == 0) {
		j = minikafs_ws_cell(local, sizeof(local));
		if ((j == 0) && (strcmp(local, "dynroot") != 0)) {
			if (log_options.debug) {
				debug("local cell is \"%s\"", local);
			}
			j = minikafs_log(NULL, ccache, &log_options,
					 local, NULL, uid, try_v5_2b);
			if (j != 0) {
				fprintf(stderr, "%s: %d\n", local, j);
			}
		}
		if (getenv("HOME") != NULL) {
			homedir = xstrdup(getenv("HOME"));
		} else {
			homedir = xstrdup("/afs");
		}
		if (homedir != NULL) {
			j = minikafs_cell_of_file_walk_up(homedir, home,
							  sizeof(home));
			if ((j == 0) &&
			    (strcmp(home, "dynroot") != 0) &&
			    (strcmp(home, local) != 0)) {
				if (log_options.debug) {
					debug("home cell is \"%s\"", home);
				}
				j = minikafs_log(NULL, ccache,
						 &log_options,
						 home, NULL, uid, try_v5_2b);
				if (j != 0) {
					fprintf(stderr, "%s: %d\n", home, j);
				}
			}
		}
	}
	krb5_free_context(ctx);
	return 0;
}
