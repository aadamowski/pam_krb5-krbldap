/*
 * Copyright 2003,2004 Red Hat, Inc.
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

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "log.h"
#include "minikafs.h"
#include "options.h"
#include "stash.h"
#include "tokens.h"
#include "userinfo.h"
#include "xstr.h"

#ident "$Id$"

int
tokens_useful(void)
{
	if (minikafs_has_afs()) {
		return 1;
	}
	return 0;
}

int
tokens_obtain(krb5_context context,
	      struct _pam_krb5_stash *stash,
	      struct _pam_krb5_options *options,
	      struct _pam_krb5_user_info *info, int newpag)
{
	int i, ret;
	char localcell[LINE_MAX], homecell[LINE_MAX], homedir[LINE_MAX],
	     lnk[LINE_MAX];
	struct stat st;
	krb5_ccache ccache;

	if (options->debug) {
		debug("obtaining afs tokens");
	}

	/* Check if AFS is running.  If it isn't, no other calls to minikafs
	 * will work, or even be safe to call. */
	if (!minikafs_has_afs()) {
		if (stat("/afs", &st) == 0) {
			warn("afs not running");
		} else {
			if (options->debug) {
				debug("afs not running");
			}
		}
		return PAM_SUCCESS;
	}

	/* Create a PAG. */
	if (newpag) {
		if (options->debug) {
			debug("creating new PAG");
		}
		minikafs_setpag();
		stash->afspag = 1;
	}

	/* Initialize the ccache. */
	memset(&ccache, 0, sizeof(ccache));
	if (stash && (stash->v5file != NULL) && (strlen(stash->v5file) > 0)) {
		if (krb5_cc_resolve(context, stash->v5file, &ccache) != 0) {
			memset(&ccache, 0, sizeof(ccache));
		}
	}

	/* Get the name of the local cell.  The root.afs volume which is
	 * mounted in /afs is mounted from the local cell, so we'll use that
	 * to determine which cell is considered the local cell.  Avoid getting
	 * tripped up by dynamic root support in clients. */
	memset(localcell, '\0', sizeof(localcell));
	if ((minikafs_cell_of_file("/afs", localcell,
				   sizeof(localcell) - 1) == 0) &&
	    (strcmp(localcell, "dynroot") != 0)) {
		if (options->debug) {
			debug("obtaining tokens for local cell '%s'",
			      localcell);
		}
		ret = minikafs_log(context, ccache, options,
				   localcell, info->uid, 0);
		if (ret != 0) {
			if (stash->v5attempted != 0) {
				warn("got error %d (%s) while obtaining "
				     "tokens for %s",
				     ret, error_message(ret), localcell);
			} else {
				if (options->debug) {
					debug("got error %d (%s) while "
					      "obtaining tokens for %s",
					      ret, error_message(ret),
					      localcell);
				}
			}
		}
	}
	/* Get the name of the cell which houses the user's home directory.  In
	 * case intervening directories aren't readable by system:anyuser
	 * (which gives us an error), keep walking the directory chain until we
	 * either succeed or run out of path components to remove.  And try to
	 * avoid doing the same thing twice. */
	strncpy(homedir, info->homedir ? info->homedir : "/afs",
		sizeof(homedir) - 1);
	homedir[sizeof(homedir) - 1] = '\0';
	/* A common configuration is to have the home directory be a symlink
	 * into /afs.  If the homedir is a symlink, chase it, *once*. */
	if (lstat(homedir, &st) == 0) {
		if (st.st_mode & S_IFLNK) {
			/* Read the link. */
			memset(lnk, '\0', sizeof(lnk));
			readlink(homedir, lnk, sizeof(lnk) - 1);
			/* If it's an absolute link, check it instead. */
			if ((strlen(lnk) > 0) && (lnk[0] == '/')) {
				strcpy(homedir, lnk);
			}
		}
	}
	do {
		memset(homecell, '\0', sizeof(homecell));
		i = minikafs_cell_of_file(homedir, homecell,
					  sizeof(homecell) - 1);
		if (i != 0) {
			if (strchr(homedir, '/') != NULL) {
				*(strrchr(homedir, '/')) = '\0';
			} else {
				strcpy(homedir, "");
			}
		}
	} while ((i != 0) && (strlen(homedir) > 0));
	if ((i == 0) &&
	    (strcmp(homecell, "dynroot") != 0) &&
	    (strcmp(homecell, localcell) != 0)) {
		if (options->debug) {
			debug("obtaining tokens for home cell '%s'", homecell);
		}
		ret = minikafs_log(context, ccache, options,
				   homecell, info->uid, 0);
		if (ret != 0) {
			if (stash->v5attempted != 0) {
				warn("got error %d (%s) while obtaining "
				     "tokens for %s",
				     ret, error_message(ret), homecell);
			} else {
				if (options->debug) {
					debug("got error %d (%s) while "
					      "obtaining tokens for %s",
					      ret, error_message(ret),
					      homecell);
				}
			}
		}
	}

	/* If there are no additional cells configured, stop here. */
	if (options->afs_cells == NULL) {
		if (options->debug) {
			debug("no additional afs cells configured");
		}
		return PAM_SUCCESS;
	}
	if (options->afs_cells[0] == NULL) {
		if (options->debug) {
			debug("no additional afs cells configured");
		}
		return PAM_SUCCESS;
	}

	/* Iterate through the list of other cells. */
	for (i = 0; options->afs_cells[i] != NULL; i++) {
		if (strcmp(options->afs_cells[i], localcell) == 0) {
			continue;
		}
		if (strcmp(options->afs_cells[i], homecell) == 0) {
			continue;
		}
		if (options->debug) {
			debug("obtaining tokens for '%s'",
			      options->afs_cells[i]);
		}
		ret = minikafs_log(context, ccache, options,
				   options->afs_cells[i], info->uid, 0);
		if (ret != 0) {
			if (stash->v5attempted != 0) {
				warn("got error %d (%s) while obtaining "
				     "tokens for %s",
				     ret, error_message(ret),
				     options->afs_cells[i]);
			} else {
				if (options->debug) {
					debug("got error %d (%s) while "
					      "obtaining tokens for %s",
					      ret, error_message(ret),
					      options->afs_cells[i]);
				}
			}
		}
	}

	if (ccache != NULL) {
		krb5_cc_close(context, ccache);
	}

	/* Suppress all errors. */
	return PAM_SUCCESS;
}

int
tokens_release(struct _pam_krb5_stash *stash, struct _pam_krb5_options *options)
{
	struct stat st;

	/* Check if AFS is running.  If it isn't, no other calls to libkrbafs
	 * will work, or even be safe to call. */
	if (!minikafs_has_afs()) {
		if (stat("/afs", &st) == 0) {
			warn("afs not running");
		} else {
			if (options->debug) {
				debug("afs not running");
			}
		}
		return PAM_SUCCESS;
	}

	/* Destroy all tokens. */
	if (stash->afspag != 0) {
		if (options->debug) {
			debug("releasing afs tokens");
		}
		minikafs_unlog();
		stash->afspag = 0;
	}

	/* Suppress all errors. */
	return PAM_SUCCESS;
}

int
tokens_getcells(struct _pam_krb5_stash *stash,
		struct _pam_krb5_options *options,
		char ***cells)
{
	int n_cells, i;
	char cell[LINE_MAX], **list;

	/* Check if AFS is running.  If it isn't, no other calls to libkrbafs
	 * will work, or even be safe to call. */
	if (!minikafs_has_afs()) {
		*cells = NULL;
		return 0;
	}

	/* Get the name of the local cell.  The root.afs volume which is
	 * mounted in /afs is mounted from the local cell, so we'll use that
	 * to determine which cell is considered the local cell. */
	memset(cell, '\0', sizeof(cell));
	if (minikafs_cell_of_file("/afs", cell, sizeof(cell) - 1) == 0) {
		n_cells = 1;
	} else {
		n_cells = 0;
		memset(cell, '\0', sizeof(cell));
	}

	/* Count the number of cells which have been explicitly configured. */
	if (options->afs_cells != NULL) {
		for (i = 0; options->afs_cells[i] != NULL; i++) {
			n_cells++;
		}
	}

	/* Create the list. */
	list = NULL;
	if (n_cells > 0) {
		list = malloc(sizeof(char*) * (n_cells + 1));
		memset(list, 0, sizeof(char*) * (n_cells + 1));
		for (i = 0; i < n_cells; i++) {
			if ((options->afs_cells != NULL) &&
			    (options->afs_cells[i] != NULL)) {
				list[i] = strdup(options->afs_cells[i]);
			} else {
				list[i] = strdup(cell);
			}
		}
	}

	*cells = list;
	return n_cells;
}

void
tokens_freelocalcells(struct _pam_krb5_stash *stash,
		      struct _pam_krb5_options *options,
		      char **cells)
{
	int i;
	if (cells == NULL) {
		return;
	}
	for (i = 0; (cells != NULL) && (cells[i] != NULL); i++) {
		free(cells[i]);
		cells[i] = NULL;
	}
	free(cells);
}
