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
#include <errno.h>
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

#include "init.h"
#include "log.h"
#include "options.h"
#include "sly.h"
#include "stash.h"
#include "tokens.h"
#include "userinfo.h"
#include "v5.h"
#include "v4.h"

#ident "$Id$"

/* These would be where we refresh the ticket and ccache files KRBTKFILE and
 * KRB5CCNAME point to, if set.  Until I figure out under what conditions that
 * can be considered safe, we're just not going to do that. */
static void
sly_v4(krb5_context ctx, const char *v4tktfile,
       struct _pam_krb5_user_info *userinfo, struct _pam_krb5_stash *stash)
{
}
static int
sly_v5(krb5_context ctx, const char *v5ccname,
       struct _pam_krb5_user_info *userinfo, struct _pam_krb5_stash *stash)
{
	return PAM_SUCCESS;
}

int
_pam_krb5_sly_maybe_refresh(pam_handle_t *pamh, int flags,
			    int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
	struct stat st;
	int i, retval;
	char *v5ccname, *v4tktfile;

	/* Initialize Kerberos. */
	if (_pam_krb5_init_ctx(&ctx, argc, argv) != 0) {
		warn("error initializing Kerberos");
		return PAM_SERVICE_ERR;
	}

	/* Get the user's name. */
	i = pam_get_user(pamh, &user, NULL);
	if (i != PAM_SUCCESS) {
		warn("could not identify user name");
		krb5_free_context(ctx);
		return i;
	}

	/* Read our options. */
	options = _pam_krb5_options_init(pamh, argc, argv, ctx);
	if (options == NULL) {
		warn("error parsing options (shouldn't happen)");
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}
	if (options->debug) {
		debug("called to update credentials for '%s'", user);
	}

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options->realm,
					    options->user_check,
					    options->n_mappings,
					    options->mappings);
	if (userinfo == NULL) {
		warn("error getting information about '%s' (shouldn't happen)",
		     user);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_USER_UNKNOWN;
	}

	if ((options->minimum_uid != -1) &&
	    (userinfo->uid < options->minimum_uid)) {
		if (options->debug) {
			debug("ignoring '%s' -- uid below minimum", user);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_IGNORE;
	}

	/* Get the stash for this user. */
	stash = _pam_krb5_stash_get(pamh, userinfo);
	if (stash == NULL) {
		warn("error retrieving stash for '%s' (shouldn't happen)",
		     user);
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* Save credentials in the right files. */
	v5ccname = getenv("KRB5CCNAME");
	if ((v5ccname != NULL) && (strncmp(v5ccname, "FILE:", 5) == 0)) {
		v5ccname += 5;
	}

	retval = PAM_SERVICE_ERR;

	if (v5ccname == NULL) {
		/* Ignore us.  We have nothing to do. */
		retval = PAM_SUCCESS;
	}

	if ((v5_creds_check_initialized(ctx, &stash->v5creds) == 0) &&
	    (v5ccname != NULL)) {
		if (access(v5ccname, R_OK | W_OK) == 0) {
			if (lstat(v5ccname, &st) == 0) {
				if (S_ISREG(st.st_mode) &&
				    (getuid() == geteuid()) &&
				    (getgid() == getegid()) &&
				    (st.st_uid == userinfo->uid) &&
				    (st.st_gid == userinfo->gid)) {
					retval = sly_v5(ctx, v5ccname,
							userinfo, stash);
				} else {
					if (options->debug) {
						debug("not updating '%s'",
						      v5ccname);
					}
				}
			} else {
				if (errno == ENOENT) {
					/* We have nothing to do. */
					retval = PAM_SUCCESS;
				}
			}
		} else {
			/* Touch nothing. */
			retval = PAM_SUCCESS;
		}
	}

	v4tktfile = getenv("KRBTKFILE");
	if ((stash->v4present) && (v4tktfile != NULL)) {
		if (access(v4tktfile, R_OK | W_OK) == 0) {
			if (lstat(v4tktfile, &st) == 0) {
				if (S_ISREG(st.st_mode) &&
				    (getuid() == geteuid()) &&
				    (getgid() == getegid()) &&
				    (st.st_uid == userinfo->uid) &&
				    (st.st_gid == userinfo->gid)) {
					sly_v4(ctx, v4tktfile, userinfo, stash);
					tokens_obtain(ctx, stash, options);
				} else {
					if (options->debug) {
						debug("not updating '%s'",
						      v4tktfile);
					}
				}
			} else {
				if (errno == ENOENT) {
					/* We have nothing to do. */
					retval = PAM_SUCCESS;
				}
			}
		} else {
			/* Touch nothing. */
			retval = PAM_SUCCESS;
		}
	}

	if (options->debug) {
		debug("_pam_krb5_sly_refresh returning %d (%s)", retval,
		      pam_strerror(pamh, retval));
	}

	return retval;
}
