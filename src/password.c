/*
 * Copyright 2003 Red Hat, Inc.
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

#ifdef HAVE_SECURITY_PAM_MODULES_H
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "init.h"
#include "initopts.h"
#include "items.h"
#include "log.h"
#include "options.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"
#include "v5.h"
#include "v4.h"
#include "xstr.h"

#ident "$Id$"

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	char prompt[LINE_MAX], prompt2[LINE_MAX], *password, *password2;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
	krb5_get_init_creds_opt gic_options;
	int tmp_result;
	int i, retval;

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
	krb5_get_init_creds_opt_init(&gic_options);
	_pam_krb5_set_init_opts(ctx, &gic_options, options);

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options->realm,
					    options->user_check);
	if (userinfo == NULL) {
		warn("error getting information about '%s'", user);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_USER_UNKNOWN;
	}

	/* Check the minimum UID argument. */
	if ((options->minimum_uid != -1) &&
	    (userinfo->uid < options->minimum_uid)) {
		if (options->debug) {
			debug("ignoring '%s' -- uid below minimum = %lu", user,
			      (unsigned long) options->minimum_uid);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_IGNORE;
	}

	/* Get the stash of credentials.  If we are interactively prompting
	 * the user for information, we're not expected to ask for the user's
	 * current password more than once, so we use it to get a changepw
	 * ticket during the first pass, and we store that for use in the
	 * second pass.  It should have a low lifetime, so we needn't free it
	 * just now. */
	retval = PAM_AUTH_ERR;
	stash = _pam_krb5_stash_get(pamh, userinfo);

	/* If this is the first pass, just check the user's password by
	 * obtaining a password-changing initial ticket. */
	if (flags & PAM_PRELIM_CHECK) {
		retval = PAM_AUTH_ERR;
		password = NULL;
		/* Obtain the current password. */
		if (options->use_authtok) {
			/* Read the stored password.  This first time around,
			 * it's the PAM_AUTHTOK item. */
			i = _pam_krb5_get_item_text(pamh, PAM_AUTHTOK,
						    &password);
			/* Duplicate the password so that we can free it later
			 * without corrupting the heap. */
			if (i == PAM_SUCCESS) {
				password = xstrdup(password);
			}
		} else {
			/* Ask the user for a password. */
			sprintf(prompt, "%s%sPassword: ",
				options->banner,
				strlen(options->banner) > 0 ? " " : "");
			i = _pam_krb5_prompt_for(pamh, prompt, &password);
			/* Save the password for possible use by other
			 * modules. */
			if (i == PAM_SUCCESS) {
				pam_set_item(pamh, PAM_AUTHTOK, &password);
			}
		}
		/* We have a password, so try to obtain initial credentials
		 * using the password. */
		if (i == PAM_SUCCESS) {
			i = v5_get_creds(ctx, pamh,
					 &stash->v5creds, userinfo, options,
					 PASSWORD_CHANGE_PRINCIPAL,
					 password, NULL,
					 &tmp_result);
			if (options->debug) {
				debug("Got %d (%s) acquiring credentials for "
				      "%s.",
				      tmp_result, v5_error_message(tmp_result),
				      PASSWORD_CHANGE_PRINCIPAL);
			}
			if (i == PAM_SUCCESS) {
				retval = PAM_SUCCESS;
			}
		}
		/* Free [the copy of] the password. */
		xstrfree(password);
	}

	/* If this is the second pass, get the new password, use the
	 * credentials which we obtained and stashed in the first pass to set
	 * the user's password, and then use the new password to obtain a TGT.
	 * (If we're changing an expired password, then we'll need it to create
	 * a ccache file later.) */
	if (flags & PAM_UPDATE_AUTHTOK) {
		retval = PAM_AUTHTOK_ERR;
		password = NULL;

		if (options->use_authtok) {
			/* The new password is stored as the PAM_AUTHTOK item.
			 * The old one is stored as the PAM_OLDAUTHTOK item,
			 * but we don't use it here. */
			i = _pam_krb5_get_item_text(pamh, PAM_AUTHTOK,
						    &password);
			/* Duplicate the password, as above. */
			if (i == PAM_SUCCESS) {
				password = xstrdup(password);
			}
		} else {
			/* Ask for the password twice. */
			sprintf(prompt, "New %s%sPassword: ",
				options->banner,
				strlen(options->banner) > 0 ? " " : "");
			sprintf(prompt2, "Repeat New %s%sPassword: ",
				options->banner,
				strlen(options->banner) > 0 ? " " : "");
			i = _pam_krb5_prompt_for_2(pamh, prompt, &password,
						   prompt2, &password2);
			/* If they're not the same, return PAM_TRY_AGAIN. */
			if (strcmp(password, password2) != 0) {
				i = PAM_TRY_AGAIN;
				retval = PAM_TRY_AGAIN;
			}
			/* Save the password for possible use by other
			 * modules. */
			if (i == 0) {
				pam_set_item(pamh, PAM_AUTHTOK, &password);
			}
			/* Free the second password, we only need one copy. */
			xstrfree(password2);
		}

		/* We have the new password, so attempt to change the user's
		 * password using the previously-acquired password-changing
		 * magic ticket. */
		if ((i == PAM_SUCCESS) &&
		    (v5_creds_check_initialized(ctx, &stash->v5creds) == 0)) {
			int result_code;
			krb5_data result_code_string, result_string;
			i = krb5_change_password(ctx, &stash->v5creds, password,
						 &result_code,
						 &result_code_string,
						 &result_string);
			if (i == 0) {
				notice("password changed for %s",
				       userinfo->unparsed_name);
				retval = PAM_SUCCESS;
			} else {
				notice("password change failed for %s: %s",
				       userinfo->unparsed_name,
				       v5_error_message(i));
			}
		}

		/* If we succeeded, obtain a new TGT using the new password. */
		if (retval == PAM_SUCCESS) {
			if (options->debug) {
				debug("obtaining credentials using new "
				      "password for '%s'",
				      userinfo->unparsed_name);
			}
			i = v5_get_creds(ctx, pamh, &stash->v5creds,
					 userinfo, options,
					 KRB5_TGS_NAME, password,
					 &gic_options, NULL);
			if ((i == PAM_SUCCESS) && (options->v4 == 1)) {
				v4_get_creds(ctx, pamh, stash, userinfo,
					     options, password, &i);
				if (i != 0) {
					if (options->debug) {
						debug("error obtaining initial credentials: %d (%s)",
						      i, v5_error_message(i));
					}
				}
			}
		}

		/* Free the new password. */
		xstrfree(password);
	}

	/* Clean up. */
	if (options->debug) {
		debug("pam_chauthtok returning %d (%s)", retval,
		      pam_strerror(pamh, retval));
	}
	_pam_krb5_user_info_free(ctx, userinfo);
	_pam_krb5_options_free(pamh, ctx, options);
	krb5_free_context(ctx);
	return retval;
}
