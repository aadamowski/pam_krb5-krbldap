/*
 * Copyright 2003,2004,2005,2006 Red Hat, Inc.
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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

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
#include "shmem.h"
#include "stash.h"
#include "storetmp.h"
#include "userinfo.h"
#include "v4.h"
#include "v5.h"
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

/* Read v5 state from the shared memory segment. */
static void
_pam_krb5_stash_shm_read_v5(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			    struct _pam_krb5_options *options, int key,
			    void *blob, size_t blob_size)
{
	char tktfile[PATH_MAX + 5];
	unsigned char *blob_creds;
	ssize_t blob_creds_size;
	int fd;
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_cc_cursor cursor;

	/* Sanity checks. */
	if (blob_size < sizeof(int) * 3) {
		warn("saved creds too small: %d bytes, need at least %d bytes",
		     blob_size, sizeof(int) * 3);
		return;
	}
	blob_creds = blob;
	blob_creds += sizeof(int) * 3;
	blob_creds_size = ((int*)blob)[0];
	if (blob_creds_size + sizeof(int) * 3 > blob_size) {
		warn("saved creds too small: %d bytes, need %d bytes",
		     blob_size, blob_creds_size + sizeof(int) * 3);
		return;
	}

	/* Create a temporary ccache file. */
	snprintf(tktfile, sizeof(tktfile),
		 "FILE:%s/pam_krb5_tmp_XXXXXX", options->ccache_dir);
	fd = mkstemp(tktfile + 5);
	if (fd == -1) {
		warn("error creating temporary file \"%s\": %s",
		     tktfile + 5, strerror(errno));
		return;
	}

	/* Store the blob's contents in the file. */
	if (_pam_krb5_write_with_retry(fd,
				       blob_creds,
				       blob_creds_size) != blob_creds_size) {
		warn("error writing temporary file \"%s\": %s",
		     tktfile + 5, strerror(errno));
		unlink(tktfile + 5);
		close(fd);
		return;
	}

	/* Read the first credential from the file. */
	if (stash->v5ctx != NULL) {
		ctx = stash->v5ctx;
	} else {
		if (_pam_krb5_init_ctx(&ctx, 0, NULL) != PAM_SUCCESS) {
			warn("error initializing kerberos");
			unlink(tktfile + 5);
			close(fd);
			return;
		}
	}
	if (krb5_cc_resolve(ctx, tktfile, &ccache) != 0) {
		warn("error creating ccache in \"%s\"", tktfile + 5);
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
		unlink(tktfile + 5);
		close(fd);
		return;
	}
	if (krb5_cc_start_seq_get(ctx, ccache, &cursor) != 0) {
		warn("error iterating through ccache in \"%s\"", tktfile + 5);
		krb5_cc_close(ctx, ccache);
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
		unlink(tktfile + 5);
		close(fd);
		return;
	}

	/* If we have an error reading the credential, there's nothing we can
	 * do at this point to recover from it. */
	if (krb5_cc_next_cred(ctx, ccache, &cursor, &stash->v5creds) == 0) {
		/* Read other variables. */
		stash->v5attempted = ((int*)blob)[1];
		stash->v5result = ((int*)blob)[2];
		if (options->debug) {
			debug("recovered v5 credentials from shared memory "
			      "segment %d", key);
		}
	}

	/* Clean up. */
	krb5_cc_end_seq_get(ctx, ccache, &cursor);
	krb5_cc_close(ctx, ccache);
	if (ctx != stash->v5ctx) {
		krb5_free_context(ctx);
	}
	unlink(tktfile + 5);
	close(fd);
}

/* Save v5 state to the shared memory segment. */
static void
_pam_krb5_stash_shm_write_v5(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			     struct _pam_krb5_options *options,
			     struct _pam_krb5_user_info *userinfo)
{
	char variable[PATH_MAX + 5];
	void *blob;
	int *intblob;
	size_t blob_size;
	int fd, key;
	krb5_context ctx;
	krb5_ccache ccache;

	/* Sanity check. */
	if ((stash->v5attempted == 0) || (stash->v5result != 0)) {
		return;
	}

	/* Create a temporary ccache file. */
	snprintf(variable, sizeof(variable),
		 "FILE:%s/pam_krb5_tmp_XXXXXX", options->ccache_dir);
	fd = mkstemp(variable + 5);
	if (fd == -1) {
		warn("error creating temporary ccache file \"%s\"",
		     variable + 5);
		return;
	}

	/* Write the credentials to that file. */
	if (stash->v5ctx != NULL) {
		ctx = stash->v5ctx;
	} else {
		if (_pam_krb5_init_ctx(&ctx, 0, NULL) != PAM_SUCCESS) {
			warn("error initializing kerberos");
			unlink(variable + 5);
			close(fd);
			return;
		}
	}
	if (krb5_cc_resolve(ctx, variable, &ccache) != 0) {
		warn("error opening credential cache file \"%s\" for writing",
		     variable + 5);
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
		unlink(variable + 5);
		close(fd);
		return;
	}
	if (krb5_cc_initialize(ctx, ccache, userinfo->principal_name) != 0) {
		warn("error initializing credential cache file \"%s\"",
		     variable + 5);
		krb5_cc_close(ctx, ccache);
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
		unlink(variable + 5);
		close(fd);
		return;
	}
	if (krb5_cc_store_cred(ctx, ccache, &stash->v5creds) != 0) {
		warn("error writing to credential cache file \"%s\"",
		     variable + 5);
		krb5_cc_close(ctx, ccache);
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
		unlink(variable + 5);
		close(fd);
		return;
	}

	/* Read the entire file. */
	key = _pam_krb5_shm_new_from_file(pamh, sizeof(int) * 3,
					  variable + 5, &blob_size, &blob,
					  options->debug);
	if ((key != -1) && (blob != NULL)) {
		intblob = blob;
		intblob[0] = blob_size;
		intblob[1] = stash->v5attempted;
		intblob[2] = stash->v5result;
	}
	if (blob != NULL) {
		blob = _pam_krb5_shm_detach(blob);
	}

	/* Clean up. */
	krb5_cc_close(ctx, ccache);
	if (ctx != stash->v5ctx) {
		krb5_free_context(ctx);
	}
	unlink(variable + 5);
	close(fd);

	if (key != -1) {
		snprintf(variable, sizeof(variable),
			 PAM_KRB5_STASH_TEMPLATE
			 PAM_KRB5_STASH_SHM5_SUFFIX
			 "=%d/%ld",
			 userinfo->unparsed_name, key, (long) getpid());
		pam_putenv(pamh, variable);
		if (options->debug) {
			debug("saved v5 credentials to shared memory "
			      "segment %d (creator pid %ld)", key,
			      (long) getpid());
		}
		stash->v5shm = key;
		stash->v5shm_owner = getpid();
	} else {
		warn("error saving v5 credential state to shared "
		     "memory segment");
	}
}

#ifdef USE_KRB4
/* Read v4 state from the shared memory segment. */
static void
_pam_krb5_stash_shm_read_v4(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			    struct _pam_krb5_options *options, int key,
			    void *blob, size_t blob_size)
{
	int *intblob;
	unsigned char *p;

	if (blob_size >= sizeof(int) * 2 + sizeof(stash->v4creds)) {
		intblob = blob;
		if (intblob[1] == sizeof(stash->v4creds)) {
			stash->v4present = intblob[0];
			p = blob;
			p += sizeof(int) * 2;
			memcpy(&stash->v4creds, p, sizeof(stash->v4creds));
			if (options->debug) {
				debug("recovered v4 credential state from "
				      "shared memory segment %d", key);
			}
		} else {
			warn("shm segment containing krb4 credential state has "
			     "wrong size (expected %lu bytes, got %lu)",
			     (unsigned long) sizeof(int) * 2 +
			    		     sizeof(stash->v4creds),
			     (unsigned long) blob_size);
		}
	} else {
		warn("shm segment containing krb4 credential state has wrong "
		     "size (expected %lu bytes, got %lu)",
		     (unsigned long) sizeof(int) * 2 + sizeof(stash->v4creds),
		     (unsigned long) blob_size);
	}
}

/* Save v4 state to the shared memory segment. */
static void
_pam_krb5_stash_shm_write_v4(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			     struct _pam_krb5_options *options,
			     struct _pam_krb5_user_info *userinfo)
{
	void *blob;
	int *intblob, key;
	char variable[PATH_MAX];
	key = _pam_krb5_shm_new_from_blob(pamh, sizeof(int) * 2,
					  &stash->v4creds,
					  sizeof(stash->v4creds),
					  &blob, options->debug);
	if ((key != -1) && (blob != NULL)) {
		intblob = blob;
		intblob[0] = stash->v4present;
		intblob[1] = sizeof(stash->v4creds);
		snprintf(variable, sizeof(variable),
			 PAM_KRB5_STASH_TEMPLATE
			 PAM_KRB5_STASH_SHM4_SUFFIX
			 "=%d/%ld",
			 userinfo->unparsed_name, key, (long) getpid());
		pam_putenv(pamh, variable);
		if (options->debug) {
			debug("saved v4 credential state to shared "
			      "memory segment %d (creator pid %ld)", key,
			      (long) getpid());
		}
		stash->v4shm = key;
		stash->v4shm_owner = getpid();
	} else {
		warn("error saving v4 credential state to shared "
		     "memory segment");
	}
	if (blob != NULL) {
		blob = _pam_krb5_shm_detach(blob);
	}
}
#endif

/* Retrieve credentials from the shared memory segments named by the PAM
 * environment variables which begin with partial_key. */
void
_pam_krb5_stash_shm_read(pam_handle_t *pamh, const char *partial_key,
			 struct _pam_krb5_stash *stash,
			 struct _pam_krb5_options *options)
{
	int key;
	pid_t owner;
	long l;
	char *variable, *p, *q;
	const char *value;
	void *blob;
	size_t blob_size;

	/* Construct the name of a variable. */
	variable = malloc(strlen(partial_key) + 10);
	if (variable == NULL) {
		return;
	}
	sprintf(variable, "%s" PAM_KRB5_STASH_SHM5_SUFFIX, partial_key);

	/* Read the variable and extract a shared memory identifier. */
	value = pam_getenv(pamh, variable);
	key = -1;
	owner = -1;
	if (value != NULL) {
		l = strtol(value, &p, 0);
		if ((p != NULL) && (*p == '/')) {
			if ((l < INT_MAX) && (l > INT_MIN)) {
				key = l;
			}
			q = NULL;
			l = strtol(p + 1, &q, 0);
			if ((q != NULL) && (*q == '\0') && (q > p + 1)) {
				owner = l;
			}
		}
	}

	/* Get a copy of the contents of the shared memory segment. */
	if ((stash->v5shm == -1) && (owner != -1)) {
		stash->v5shm = key;
		stash->v5shm_owner = owner;
	}
	if (key != -1) {
		_pam_krb5_blob_from_shm(key, &blob, &blob_size);
		if ((blob == NULL) || (blob_size == 0)) {
			warn("no segment with specified identifier %d", key);
		} else {
			/* Pull credentials from the blob, which contains a
			 * ccache file.  Cross our fingers and hope it's
			 * useful. */
			_pam_krb5_stash_shm_read_v5(pamh, stash,
						    options, key,
						    blob, blob_size);
			free(blob);
		}
	}

#ifdef USE_KRB4
	/* Construct the name of a variable. */
	sprintf(variable, "%s" PAM_KRB5_STASH_SHM4_SUFFIX, partial_key);

	/* Read the variable and extract a shared memory identifier. */
	value = pam_getenv(pamh, variable);
	key = -1;
	owner = -1;
	if (value != NULL) {
		l = strtol(value, &p, 0);
		if ((p != NULL) && (*p == '/')) {
			if ((l < INT_MAX) && (l > INT_MIN)) {
				key = l;
			}
			q = NULL;
			l = strtol(p + 1, &q, 0);
			if ((q != NULL) && (*q == '\0') && (q > p + 1)) {
				owner = l;
			}
		}
	}

	/* Get a copy of the contents of the shared memory segment. */
	if ((stash->v4shm == -1) && (owner != -1)) {
		stash->v4shm = key;
		stash->v4shm_owner = owner;
	}
	if (key != -1) {
		_pam_krb5_blob_from_shm(key, &blob, &blob_size);
		if ((blob == NULL) || (blob_size == 0)) {
			warn("no segment with specified identifier %d", key);
		} else {
			/* Pull credentials from the blob, which contains a
			 * credentials structure.  Cross our fingers and hope
			 * it's useful. */
			_pam_krb5_stash_shm_read_v4(pamh, stash, options,
						    key, blob, blob_size);
			free(blob);
		}
	}
#endif

	free(variable);
}

/* Store credentials in new shared memory segments and set PAM environment
 * variables to their identifiers. */
void
_pam_krb5_stash_shm_write(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			  struct _pam_krb5_options *options,
			  struct _pam_krb5_user_info *userinfo)
{
	_pam_krb5_stash_shm_write_v5(pamh, stash, options, userinfo);
#ifdef USE_KRB4
	_pam_krb5_stash_shm_write_v4(pamh, stash, options, userinfo);
#endif
}

/* Check for KRB5CCNAME and KRBTKFILE in the PAM environment.  If either
 * exists, incorporate contents of the named ccache/tktfiles into the stash. */
static void
_pam_krb5_stash_external_read(pam_handle_t *pamh, struct _pam_krb5_stash *stash,
			      struct _pam_krb5_user_info *userinfo,
			      struct _pam_krb5_options *options)
{
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_principal princ;
	krb5_cc_cursor cursor;
	int i, read_default_principal;
	const char *ccname;
	char *unparsed;

	/* Read a TGT from $KRB5CCNAME. */
	ccname = pam_getenv(pamh, "KRB5CCNAME");
	if ((ccname != NULL) && (strlen(ccname) > 0)) {
		if (options->debug) {
			debug("KRB5CCNAME is set to \"%s\"", ccname);
		}
		if (stash->v5ctx != NULL) {
			ctx = stash->v5ctx;
		} else {
			if (_pam_krb5_init_ctx(&ctx, 0, NULL) != PAM_SUCCESS) {
				warn("error initializing kerberos");
				return;
			}
		}
		ccache = NULL;
		read_default_principal = 0;
		i = krb5_cc_resolve(ctx, ccname, &ccache);
		if (i != 0) {
			warn("error opening ccache \"%s\", ignoring", ccname);
		} else {
			princ = NULL;
			/* Read the name of the default principal from the
			 * ccache. */
			if (krb5_cc_get_principal(ctx, ccache, &princ) != 0) {
				warn("error reading ccache's default principal name");
			} else {
				read_default_principal++;
				/* If they're different, update the userinfo
				 * structure with the new principal name. */
				if (krb5_principal_compare(ctx, princ,
							   userinfo->principal_name)) {
					if (options->debug) {
						debug("ccache matches current principal");
					}
					krb5_free_principal(ctx, princ);
					princ = NULL;
				} else {
					if (options->debug) {
						debug("ccache is for a different principal, updating");
					}
					/* Unparse the name. */
					unparsed = NULL;
					if (krb5_unparse_name(ctx, princ, &unparsed) != 0) {
						warn("error unparsing ccache's default principal name, discarding");
						krb5_free_principal(ctx, princ);
						princ = NULL;
					} else {
						if (options->debug) {
							debug("updated user principal from '%s' to '%s'",
							      userinfo->unparsed_name,
							      unparsed);
						}
						/* Save the unparsed name. */
						v5_free_unparsed_name(ctx, userinfo->unparsed_name);
						userinfo->unparsed_name = unparsed;
						unparsed = NULL;
						/* Save the principal name. */
						krb5_free_principal(ctx, userinfo->principal_name);
						userinfo->principal_name = princ;
						princ = NULL;
					}
				}
			}
			/* If we were able to read the default principal, then
			 * search for a TGT. */
			cursor = NULL;
			if (read_default_principal &&
			    (krb5_cc_start_seq_get(ctx, ccache, &cursor) == 0)) {
				memset(&stash->v5creds, 0, sizeof(stash->v5creds));
				while (krb5_cc_next_cred(ctx, ccache, &cursor,
							 &stash->v5creds) == 0) {
					unparsed = NULL;
					i = krb5_unparse_name(ctx,
							      stash->v5creds.server,
							      &unparsed);
					if ((i == 0) && (unparsed != NULL)) {
						i = strcspn(unparsed,
							    PAM_KRB5_PRINCIPAL_COMPONENT_SEPARATORS);
						if ((i == KRB5_TGS_NAME_SIZE) &&
						    (strncmp(unparsed,
							     KRB5_TGS_NAME,
							     KRB5_TGS_NAME_SIZE) == 0)) {
							if (options->debug) {
								debug("using credential for \"%s\" as a v5 TGT", unparsed);
							}
							v5_free_unparsed_name(ctx, unparsed);
							unparsed = NULL;
							stash->v5attempted = 1;
							stash->v5result = 0;
							break;
						}
						if (options->debug) {
							debug("not using credential for \"%s\" as a v5 TGT", unparsed);
						}
						v5_free_unparsed_name(ctx, unparsed);
						unparsed = NULL;
					}
					krb5_free_cred_contents(ctx, &stash->v5creds);
					memset(&stash->v5creds, 0, sizeof(stash->v5creds));
				}
				krb5_cc_end_seq_get(ctx, ccache, &cursor);
			}
			krb5_cc_close(ctx, ccache);
		}
		if (ctx != stash->v5ctx) {
			krb5_free_context(ctx);
		}
	}

#if 0
#ifdef USE_KRB4
	const char *v4tktname; /* FIXME: not available before C99! */
	/* Read a TGT from $KRBTKFILE. */
	v4tktname = pam_getenv(pamh, "KRBTKFILE");
	if ((v4tktname != NULL) && (strlen(v4tktname) > 0) &&
	    (stash->v4present == 0)) {
		char name[ANAME_SZ + 1], instance[INST_SZ + 1],
		     realm[REALM_SZ + 1];

		if (tf_init(pam_getenv(pamh, "KRBTKFILE"), R_TKT_FILE) == 0) {
			if ((tf_get_pname(name) == 0) &&
			    (tf_get_pinst(instance) == 0)) {
				while (tf_get_cred(&stash->v4creds) == 0) {
					if (strncmp(stash->v4creds.service,
						    KRB5_TGS_NAME,
						    KRB5_TGS_NAME_SIZE) == 0) {
	    					stash->v4present = 1;
						break;
					}
				}
			}
			tf_close();
		}
	}
#endif
#endif
}

/* Get the stash of lookaside data we keep about this user.  If we don't
 * already have one, we need to create it.  We use a data name which includes
 * the principal name to allow checks within multiple realms to work, and we
 * store the key in the stash because older versions of libpam stored the
 * pointer instead of making their own copy of the key, which could lead to
 * crashes if we then deallocated the string. */
struct _pam_krb5_stash *
_pam_krb5_stash_get(pam_handle_t *pamh, struct _pam_krb5_user_info *info,
		    struct _pam_krb5_options *options)
{
	krb5_context ctx;
	struct _pam_krb5_stash *stash;
	char *key;

	key = malloc(strlen(PAM_KRB5_STASH_TEMPLATE) +
		     strlen(info->unparsed_name) +
		     1);
	if (key == NULL) {
		return NULL;
	}
	sprintf(key, PAM_KRB5_STASH_TEMPLATE, info->unparsed_name);

	stash = NULL;
	if ((_pam_krb5_get_data_stash(pamh, key, &stash) == PAM_SUCCESS) &&
	    (stash != NULL)) {
	    	free(key);
		if (options->external && (stash->v5attempted == 0)) {
			_pam_krb5_stash_external_read(pamh, stash,
						      info, options);
			if (stash->v5attempted && (stash->v5result == 0)) {
				if ((_pam_krb5_init_ctx(&ctx, 0, NULL) == 0) &&
				    ((options->v4 == 1) || (options->v4_for_afs == 1))) {
					v4_get_creds(ctx, pamh, stash,
						     info, options, NULL, NULL);
					krb5_free_context(ctx);
				}
			}
		}
		return stash;
	}

	stash = malloc(sizeof(struct _pam_krb5_stash));
	if (stash == NULL) {
	    	free(key);
		return NULL;
	}
	memset(stash, 0, sizeof(struct _pam_krb5_stash));

	stash->key = key;
	stash->v5ctx = NULL;
	stash->v5attempted = 0;
	stash->v5result = KRB5KRB_ERR_GENERIC;
	stash->v5file = NULL;
	stash->v5setenv = 0;
	stash->v5shm = -1;
	stash->v5shm_owner = -1;
	memset(&stash->v5creds, 0, sizeof(stash->v5creds));
	stash->v4present = 0;
#ifdef USE_KRB4
	memset(&stash->v4creds, 0, sizeof(stash->v4creds));
	stash->v4file = NULL;
	stash->v4setenv = 0;
	stash->v4shm = -1;
	stash->v4shm_owner = -1;
#endif
	stash->afspag = 0;
	if (options->use_shmem) {
		_pam_krb5_stash_shm_read(pamh, key, stash, options);
	}
	if (options->external && (stash->v5attempted == 0)) {
		_pam_krb5_stash_external_read(pamh, stash, info, options);
		if (stash->v5attempted && (stash->v5result == 0)) {
			if ((_pam_krb5_init_ctx(&ctx, 0, NULL) == 0) &&
			    ((options->v4 == 1) || (options->v4_for_afs == 1))) {
				v4_get_creds(ctx, pamh, stash, info,
					     options, NULL, NULL);
				krb5_free_context(ctx);
			}
		}
	}
	pam_set_data(pamh, key, stash, _pam_krb5_stash_cleanup);

	return stash;
}

static void
_pam_krb5_stash_clone(char **stored_file, void **copy, size_t *copy_len,
		      uid_t uid, gid_t gid)
{
	char *filename;
	size_t length;
	if (*stored_file != NULL) {
		filename = strdup(*stored_file);
		length = strlen(filename);
		if (length > 6) {
			strcpy(filename + length - 6, "XXXXXX");
			if (_pam_krb5_storetmp_file(*stored_file,
						    filename,
						    copy, copy_len,
						    uid, gid,
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
	_pam_krb5_stash_clone(&stash->v5file, NULL, NULL, uid, gid);
}

#ifdef USE_KRB4
void
_pam_krb5_stash_clone_v4(struct _pam_krb5_stash *stash, uid_t uid, gid_t gid)
{
	_pam_krb5_stash_clone(&stash->v4file, NULL, NULL, uid, gid);
}
#else
void
_pam_krb5_stash_clone_v4(struct _pam_krb5_stash *stash, uid_t uid, gid_t gid)
{
}
#endif

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

#ifdef USE_KRB4
int
_pam_krb5_stash_clean_v4(struct _pam_krb5_stash *stash)
{
	return _pam_krb5_stash_clean(&stash->v4file);
}
#else
int
_pam_krb5_stash_clean_v4(struct _pam_krb5_stash *stash)
{
	return 0;
}
#endif

int
_pam_krb5_stash_clean_v5(struct _pam_krb5_stash *stash)
{
	return _pam_krb5_stash_clean(&stash->v5file);
}
