#include "../config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

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
#ifdef USE_AFS
#include KRB4_AFS_H
#endif

#include "log.h"
#include "options.h"
#include "tokens.h"

#ident "$Id$"

#ifdef USE_AFS
int
tokens_obtain(struct _pam_krb5_options *options)
{
	int i;
	char cell[LINE_MAX];
	struct stat st;

	if (options->debug) {
		debug("obtaining afs tokens");
	}

	/* Check if AFS is running.  If it isn't, no other calls to libkrbafs
	 * will work, or even be safe to call. */
	if (!k_hasafs()) {
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
	k_setpag();

	/* Get the name of the local cell.  The root.afs volume which is
	 * mounted in /afs is mounted from the local cell, so we'll use that
	 * to determine which cell is considered the local cell. */
	memset(cell, '\0', sizeof(cell));
	if (k_afs_cell_of_file("/afs", cell, sizeof(cell) - 1) == 0) {
		if (options->debug) {
			debug("obtaining tokens for '%s'", cell);
		}
		krb_afslog(cell, options->realm);
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
		if (options->debug) {
			debug("obtaining tokens for '%s'",
			      options->afs_cells[i]);
		}
		krb_afslog(options->afs_cells[i], options->realm);
	}

	/* Suppress all errors. */
	return PAM_SUCCESS;
}

int
tokens_release(struct _pam_krb5_options *options)
{
	struct stat st;

	/* Check if AFS is running.  If it isn't, no other calls to libkrbafs
	 * will work, or even be safe to call. */
	if (!k_hasafs()) {
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
	if (options->debug) {
		debug("releasing afs tokens");
	}
	k_unlog();

	/* Suppress all errors. */
	return PAM_SUCCESS;
}
#else
int
tokens_obtain(struct _pam_krb5_options *options)
{
	if (options->debug) {
		debug("afs support not compiled");
	}
	return PAM_SUCCESS;
}
int
tokens_release(struct _pam_krb5_options *options)
{
	if (options->debug) {
		debug("afs support not compiled");
	}
	return PAM_SUCCESS;
}
#endif
