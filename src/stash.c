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
#include "stash.h"
#include "storetmp.h"
#include "userinfo.h"
#include "xstr.h"

#ident "$Id$"

static int
_pam_krb5_get_data_stash(pam_handle_t *pamh, const char *key,
			 struct _pam_krb5_stash **stash)
{
	return pam_get_data(pamh, key, (PAM_KRB5_MAYBE_CONST void**) stash);
}

/* Clean up a stash.  This includes freeing any dynamically-allocated bits and
 * then freeing the stash itself. */
static void
_pam_krb5_stash_cleanup(pam_handle_t *pamh, void *data, int error)
{
	struct _pam_krb5_stash *stash = data;
	krb5_free_cred_contents(stash->v5ctx, &stash->v5creds);
	free(stash->key);
	if (stash->v5file != NULL) {
		xstrfree(stash->v5file);
	}
#ifdef USE_KRB4
	if (stash->v4file != NULL) {
		xstrfree(stash->v4file);
	}
#endif
	memset(stash, 0, sizeof(struct _pam_krb5_stash));
	free(stash);
}

/* Get the stash of lookaside data we keep about this user.  If we don't
 * already have one, we need to create it.  We use a data name which includes
 * the principal name to allow checks within multiple realms to work, and we
 * store the key in the stash because older versions of libpam stored the
 * pointer instead of making their own copy of the key, which could lead to
 * crashes if we then deallocated the string. */
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
	stash->v5ctx = NULL;
	stash->v5attempted = 0;
	stash->v5result = KRB5KRB_ERR_GENERIC;
	stash->v5file = NULL;
	memset(&stash->v5creds, 0, sizeof(stash->v5creds));
#ifdef USE_KRB4
	stash->v4present = 0;
	memset(&stash->v4creds, 0, sizeof(stash->v4creds));
	stash->v4file = NULL;
#endif
#ifdef USE_AFS
	stash->afspag = 0;
#endif
	pam_set_data(pamh, key, stash, _pam_krb5_stash_cleanup);

	return stash;
}

static void
_pam_krb5_stash_clone(char **stored_file, uid_t uid, gid_t gid)
{
	char *filename;
	size_t length;
	if (*stored_file != NULL) {
		filename = strdup(*stored_file);
		length = strlen(filename);
		if (length > 6) {
			strcpy(filename + length - 6, "XXXXXX");
			if (_pam_krb5_storetmp_file(*stored_file,
						    filename, uid, gid,
						    filename,
						    length + 1) == 0) {
				unlink(*stored_file);
				xstrfree(*stored_file);
				*stored_file = filename;
			}
		}
		if (*stored_file != filename) {
			free(filename);
		}
	}
}

void
_pam_krb5_stash_clone_v5(struct _pam_krb5_stash *stash, uid_t uid, gid_t gid)
{
	_pam_krb5_stash_clone(&stash->v5file, uid, gid);
}

void
_pam_krb5_stash_clone_v4(struct _pam_krb5_stash *stash, uid_t uid, gid_t gid)
{
	_pam_krb5_stash_clone(&stash->v4file, uid, gid);
}

static int
_pam_krb5_stash_clean(char **stored_file)
{
	if (_pam_krb5_storetmp_delete(*stored_file) == 0) {
		xstrfree(*stored_file);
		*stored_file = NULL;
		return 0;
	} else {
		if (unlink(*stored_file) == 0) {
			xstrfree(*stored_file);
			*stored_file = NULL;
			return 0;
		}
	}
	return -1;
}

int
_pam_krb5_stash_clean_v4(struct _pam_krb5_stash *stash)
{
	return _pam_krb5_stash_clean(&stash->v4file);
}

int
_pam_krb5_stash_clean_v5(struct _pam_krb5_stash *stash)
{
	return _pam_krb5_stash_clean(&stash->v5file);
}
