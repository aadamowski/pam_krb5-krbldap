#include "../config.h"

#include <stdio.h>
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

#include "log.h"
#include "stash.h"
#include "userinfo.h"
#include "xstr.h"

#ident "$Id$"

static int
_pam_krb5_get_data_stash(pam_handle_t *pamh, const char *key,
			 struct _pam_krb5_stash **stash)
{
	return pam_get_data(pamh, key, (PAM_KRB5_MAYBE_CONST void**) stash);
}

static void
_pam_krb5_stash_cleanup(pam_handle_t *pamh, void *data, int error)
{
	struct _pam_krb5_stash *stash = data;
	krb5_free_cred_contents(stash->v5ctx, &stash->v5creds);
	free(stash->key);
	if (stash->v5file != NULL) {
		free(stash->v5file);
	}
#ifdef USE_KRB4
	if (stash->v4file != NULL) {
		free(stash->v4file);
	}
#endif
	memset(stash, 0, sizeof(struct _pam_krb5_stash));
	free(stash);
}

struct _pam_krb5_stash *
_pam_krb5_stash_get(pam_handle_t *pamh, struct _pam_krb5_user_info *info)
{
	struct _pam_krb5_stash *stash;
	char *key;

	key = malloc(strlen("_pam_krb5_stash_") +
		     strlen(info->unparsed_name) +
		     1);
	if (key == NULL) {
		return NULL;
	}
	sprintf(key, "_pam_krb5_stash_%s", info->unparsed_name);

	stash = NULL;
	if ((_pam_krb5_get_data_stash(pamh, key, &stash) == PAM_SUCCESS) &&
	    (stash != NULL)) {
		return stash;
	}

	stash = malloc(sizeof(struct _pam_krb5_stash));
	if (stash == NULL) {
		return NULL;
	}
	memset(stash, 0, sizeof(struct _pam_krb5_stash));

	stash->key = key;
	stash->v5result = KRB5KRB_ERR_GENERIC;
	pam_set_data(pamh, key, stash, _pam_krb5_stash_cleanup);

	return stash;
}
