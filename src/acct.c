#include "../config.h"

#ifdef HAVE_SECURITY_PAM_MODULES_H
#define PAM_SM_ACCT_MGMT
#include <security/pam_modules.h>
#endif

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
#include "log.h"
#include "options.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"
#include "v5.h"
#include "v4.h"

#ident "$Id$"

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
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

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options->realm,
					    options->user_check);
	if (userinfo == NULL) {
		warn("error getting information about '%s'", user);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
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

	/* Get the stash for this user. */
	stash = _pam_krb5_stash_get(pamh, userinfo);
	if (stash == NULL) {
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* Now check what happened when we asked for initial credentials. */
	switch (stash->v5result) {
	case 0:
		if (options->debug) {
			debug("account management succeeds for '%s'", user);
		}
		retval = PAM_SUCCESS;
		break;
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	case KRB5KDC_ERR_NAME_EXP:
		notice("account checks fail for '%s': user is unknown",
		       user);
		retval = PAM_USER_UNKNOWN;
		break;
	case KRB5KDC_ERR_KEY_EXP:
		notice("account checks fail for '%s': password has expired",
		       user);
		retval = PAM_NEW_AUTHTOK_REQD;
		break;
	default:
		notice("account checks fail for '%s': unknown reason %d (%s)",
		       user, stash->v5result,
		       v5_error_message(stash->v5result));
		retval = PAM_SERVICE_ERR;
		break;
	}

	/* If we got this far, check the target user's .k5login file. */
	if (retval == PAM_SUCCESS) {
		if (krb5_kuserok(ctx, userinfo->principal_name, user) == 0) {
			notice("account checks fail for '%s': user disallowed "
			       "by .k5login file for '%s'",
			       userinfo->unparsed_name, user);
			retval = PAM_PERM_DENIED;
		}
	}

	/* Clean up. */
	if (options->debug) {
		debug("pam_acct_mgmt returning %d (%s)", retval,
		      pam_strerror(pamh, retval));
	}
	_pam_krb5_options_free(pamh, ctx, options);
	_pam_krb5_user_info_free(ctx, userinfo);
	krb5_free_context(ctx);

	return retval;
}
