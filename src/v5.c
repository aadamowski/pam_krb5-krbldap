/*
 * Copyright 2003,2004,2005,2006,2007 Red Hat, Inc.
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

#include KRB5_H
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#ifndef HAVE_ERROR_MESSAGE_DECL
#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#elif defined(HAVE_ET_COM_ERR_H)
#include <et/com_err.h>
#endif
#endif

#include "conv.h"
#include "log.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"
#include "v5.h"
#include "xstr.h"

#ident "$Id$"

#ifndef KRB5_KPASSWD_ACCESSDENIED
#define KRB5_KPASSWD_ACCESSDENIED 5
#endif
#ifndef KRB5_KPASSWD_BAD_VERSION
#define KRB5_KPASSWD_BAD_VERSION  6
#endif
#ifndef KRB5_KPASSWD_INITIAL_FLAG_NEEDED
#define KRB5_KPASSWD_INITIAL_FLAG_NEEDED 7
#endif

const char *
v5_error_message(krb5_error_code error)
{
	return error_message(error);
}
const char *
v5_passwd_error_message(int error)
{
	switch (error) {
	case KRB5_KPASSWD_SUCCESS:
		return "Success";
		break;
	case KRB5_KPASSWD_MALFORMED:
		return "Malformed request";
		break;
	case KRB5_KPASSWD_HARDERROR:
		return "Password change failed";
		break;
	case KRB5_KPASSWD_AUTHERROR:
		return "Authentication error";
		break;
	case KRB5_KPASSWD_SOFTERROR:
		return "Password change rejected";
		break;
	case KRB5_KPASSWD_ACCESSDENIED:
		return "Access denied";
		break;
	case KRB5_KPASSWD_BAD_VERSION:
		return "Bad version";
		break;
	case KRB5_KPASSWD_INITIAL_FLAG_NEEDED:
		return "Attempted to authenticate using non-initial credentials";
		break;
	}
	return "Unknown error";
}

krb5_error_code
v5_alloc_get_init_creds_opt(krb5_context ctx, krb5_get_init_creds_opt **opt)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC_FREE
	/* Do NOT call krb5_get_init_creds_opt_init(), which in both Heimdal
	 * and MIT Kerberos cause the structure to be marked as not having
	 * extended data members which are used to store preauth and pkinit
	 * settings. */
	*opt = NULL;
	return krb5_get_init_creds_opt_alloc(ctx, opt);
#else
	*opt = malloc(sizeof(**opt));
	if (*opt != NULL) {
		memset(*opt, 0, sizeof(**opt));
		return 0;
	} else {
		return ENOMEM;
	}
#endif
}

void
v5_free_get_init_creds_opt(krb5_context ctx, krb5_get_init_creds_opt *opt)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC_FREE
#ifdef KRB5_GET_INIT_CREDS_OPT_ALLOC_FREE_TAKES_2_ARGS
	krb5_get_init_creds_opt_free(ctx, opt);
#else
	krb5_get_init_creds_opt_free(opt);
#endif
#else
	free(opt);
#endif
}

char *
v5_user_info_subst(krb5_context ctx,
		   const char *user,
		   struct _pam_krb5_user_info *userinfo,
		   struct _pam_krb5_options *options,
		   const char *template_value)
{
	char *ret;
	int i, j, len;
	ret = NULL;
	len = strlen(template_value);
	for (i = 0; template_value[i] != '\0'; i++) {
		switch (template_value[i]) {
		case '%':
			switch (template_value[i + 1]) {
			case 'p':
				len += strlen(userinfo->unparsed_name);
				i++;
				break;
			case 'u':
				len += strlen(user);
				i++;
				break;
			case 'U':
				len += sizeof(userinfo->uid) * 4;
				i++;
				break;
			case 'P':
				len += sizeof(pid_t) * 4;
				i++;
				break;
			case 'r':
				len += strlen(options->realm);
				i++;
				break;
			case 'h':
				len += strlen(userinfo->homedir ?
					      userinfo->homedir :
					      "/");
				i++;
			case 'd':
				len += strlen(options->ccache_dir);
				i++;
				break;
				break;
			default:
			case '%':
				break;
			}
		default:
			break;
		}
	}
	ret = malloc(len + 1);
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, '\0', len + 1);
	for (i = 0, j = 0; template_value[i] != '\0'; i++) {
		switch (template_value[i]) {
		case '%':
			switch (template_value[i + 1]) {
			case 'p':
				strcat(ret, userinfo->unparsed_name);
				i++;
				j = strlen(ret);
				break;
			case 'u':
				strcat(ret, user);
				i++;
				j = strlen(ret);
				break;
			case 'U':
				sprintf(ret + j, "%ld", (long) userinfo->uid);
				i++;
				j = strlen(ret);
				break;
			case 'P':
				sprintf(ret + j, "%ld", (long) getpid());
				i++;
				j = strlen(ret);
				break;
			case 'r':
				strcat(ret, options->realm);
				i++;
				j = strlen(ret);
				break;
			case 'h':
				strcat(ret,
				       userinfo->homedir ?
				       userinfo->homedir : "/");
				i++;
				j = strlen(ret);
				break;
			case 'd':
				strcat(ret, options->ccache_dir);
				i++;
				j = strlen(ret);
				break;
			case '%':
				strcat(ret, "%");
				i++;
				j = strlen(ret);
				break;
			default:
				strcat(ret, "%");
				j = strlen(ret);
				break;
			}
			break;
		default:
			ret[j++] = template_value[i];
			break;
		}
	}
	ret[j] = '\0';
	return ret;
}

#ifdef HAVE_KRB5_FREE_UNPARSED_NAME
void
v5_free_unparsed_name(krb5_context ctx, char *name)
{
	krb5_free_unparsed_name(ctx, name);
}
#else
void
v5_free_unparsed_name(krb5_context ctx, char *name)
{
	xstrfree(name);
}
#endif

#ifdef HAVE_KRB5_FREE_DEFAULT_REALM
void
v5_free_default_realm(krb5_context ctx, char *realm)
{
	krb5_free_default_realm(ctx, realm);
}
#else
void
v5_free_default_realm(krb5_context ctx, char *realm)
{
	xstrfree(realm);
}
#endif

#ifdef HAVE_KRB5_SET_PRINCIPAL_REALM
int
v5_set_principal_realm(krb5_context ctx, krb5_principal *principal,
		       const char *realm)
{
	return krb5_set_principal_realm(ctx, *principal, realm);
}
#else
int
v5_set_principal_realm(krb5_context ctx, krb5_principal *principal,
		       const char *realm)
{
	char *unparsed, *tmp;
	int i;
	if (krb5_unparse_name(ctx, *principal, &unparsed) == 0) {
		tmp = malloc(strlen(unparsed) + 1 + strlen(realm) + 1);
		if (tmp != NULL) {
			strcpy(tmp, unparsed);
			if (strchr(tmp, '@') != NULL) {
				strcpy(strchr(tmp, '@') + 1, realm);
			} else {
				strcat(tmp, "@");
				strcat(tmp, realm);
			}
			i = krb5_parse_name(ctx, tmp, principal);
			v5_free_unparsed_name(ctx, unparsed);
			xstrfree(tmp);
			return i;
		}
	}
	return KRB5KRB_ERR_GENERIC;
}
#endif

#if defined(HAVE_STRUCT_KRB5_PRINCIPAL_DATA_DATA)
static int
v5_principal_compare(krb5_context ctx, krb5_principal princ, const char *name)
{
	int i;
	krb5_principal temp;
	krb5_data *c1, *c2;
	temp = NULL;
	if ((i = krb5_parse_name(ctx, name, &temp)) != 0) {
		return i;
	}
	if (krb5_princ_size(ctx, princ) != krb5_princ_size(ctx, temp)) {
		krb5_free_principal(ctx, temp);
		return 1;
	}
	for (i = 0; i < krb5_princ_size(ctx, princ); i++) {
		c1 = krb5_princ_component(ctx, princ, i);
		c2 = krb5_princ_component(ctx, temp, i);
		if ((c1->length != c2->length) ||
		    (memcmp(c1->data, c2->data, c1->length) != 0)) {
			break;
		}
	}
	krb5_free_principal(ctx, temp);
	if (i == krb5_princ_size(ctx, princ)) {
		return 0;
	}
	return 1;
}
#elif defined(HAVE_STRUCT_PRINCIPAL_NAME)
static int
v5_principal_compare(krb5_context ctx, krb5_principal princ, const char *name)
{
	if (princ->name.name_string.len != strlen(name)) {
		return 1;
	}
	if (memcmp(princ->name.name_string.val, name,
		   princ->name.name_string.len) != 0) {
		return 1;
	}
	return 0;
}
#endif

#if defined(HAVE_KRB5_CREDS_KEYBLOCK) && defined(HAVE_KRB5_KEYBLOCK_ENCTYPE)
int
v5_creds_get_etype(krb5_context ctx, krb5_creds *creds)
{
	return creds->keyblock.enctype;
}
void
v5_creds_set_etype(krb5_context ctx, krb5_creds *creds, int etype)
{
	creds->keyblock.enctype = etype;
}
int
v5_creds_check_initialized(krb5_context ctx, krb5_creds *creds)
{
	return ((creds->client != NULL) &&
	        (creds->server != NULL) &&
	        (creds->keyblock.length > 0) &&
	        (creds->ticket.length > 0)) ? 0 : 1;
}
int
v5_creds_check_initialized_pwc(krb5_context ctx, krb5_creds *creds)
{
	return ((creds->client != NULL) &&
	        (creds->server != NULL) &&
	        (creds->keyblock.length > 0) &&
	        (creds->ticket.length > 0) &&
		(creds->server->length >= 2) &&
		(v5_principal_compare(ctx, creds->server,
				      PASSWORD_CHANGE_PRINCIPAL) == 0)) ? 0 : 1;
}
int
v5_creds_key_length(krb5_creds *creds)
{
	return creds->keyblock.length;
}
unsigned char *
v5_creds_key_contents(krb5_creds *creds)
{
	return creds->keyblock.contents;
}
#elif defined(HAVE_KRB5_CREDS_SESSION) && defined(HAVE_KRB5_KEYBLOCK_KEYTYPE)
int
v5_creds_get_etype(krb5_context ctx, krb5_creds *creds)
{
	return creds->session.keytype;
}
void
v5_creds_set_etype(krb5_context ctx, krb5_creds *creds, int etype)
{
	creds->session.keytype = etype;
}
int
v5_creds_check_initialized(krb5_context ctx, krb5_creds *creds)
{
	return (creds->session.keyvalue.length > 0) ? 0 : 1;
}
int
v5_creds_check_initialized_pwc(krb5_context ctx, krb5_creds *creds)
{
	return ((creds->session.keyvalue.length > 0) &&
		(v5_principal_compare(ctx, creds->server,
				      PASSWORD_CHANGE_PRINCIPAL) == 0)) ? 0 : 1;
}
int
v5_creds_key_length(krb5_creds *creds)
{
	return creds->session.keyvalue.length;
}
unsigned char *
v5_creds_key_contents(krb5_creds *creds)
{
	return creds->session.keyvalue.data;
}
#else
#error "Don't know how to read/write key types for your Kerberos implementation!"
#endif

#ifdef HAVE_KRB5_CONST_REALM
void
v5_appdefault_string(krb5_context ctx,
		     const char *realm, const char *option,
		     const char *default_value, char **ret_value)
{
	char *tmp;

	*ret_value = tmp = xstrdup(default_value);
	krb5_appdefault_string(ctx, PAM_KRB5_APPNAME, realm, option,
			       default_value, ret_value);
	if (*ret_value != tmp) {
		xstrfree(tmp);
	}
}
void
v5_appdefault_boolean(krb5_context ctx,
		      const char *realm, const char *option,
		      krb5_boolean default_value, krb5_boolean *ret_value)
{
	*ret_value = default_value;
	krb5_appdefault_boolean(ctx, PAM_KRB5_APPNAME, realm, option,
			        default_value, ret_value);
}
#else
static krb5_data *
data_from_string(const char *s)
{
	krb5_data *ret;
	ret = malloc(sizeof(krb5_data));
	if (ret == NULL) {
		return ret;
	}
	memset(ret, 0, sizeof(krb5_data));
	ret->length = xstrlen(s);
	ret->data = xstrdup(s);
	return ret;
}
static void
data_free(krb5_data *data)
{
	memset(data->data, 0, data->length);
	free(data->data);
	free(data);
}
void
v5_appdefault_string(krb5_context ctx,
		     const char *realm, const char *option,
		     const char *default_value, char **ret_value)
{
	krb5_data *realm_data;
	char *tmp;

	realm_data = data_from_string(realm);
	*ret_value = tmp = xstrdup(default_value);
	if (realm_data != NULL) {
		krb5_appdefault_string(ctx, PAM_KRB5_APPNAME, realm_data,
				       option, default_value, ret_value);
		data_free(realm_data);
	} else {
		*ret_value = xstrdup(default_value);
	}
	if (*ret_value != tmp) {
		xstrfree(tmp);
	}
}
void
v5_appdefault_boolean(krb5_context ctx,
		      const char *realm, const char *option,
		      krb5_boolean default_value, krb5_boolean *ret_value)
{
	krb5_data *realm_data;
	int tmp;

	*ret_value = default_value;

	realm_data = data_from_string(realm);
	if (realm_data != NULL) {
		krb5_appdefault_boolean(ctx, PAM_KRB5_APPNAME, realm_data,
					option, default_value, &tmp);
		*ret_value = tmp;
		data_free(realm_data);
	}
}
#endif

static int
v5_validate(krb5_context ctx, krb5_creds *creds,
	    const struct _pam_krb5_options *options)
{
	int i;
	char *principal;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_verify_init_creds_opt opt;

	/* Open the keytab. */
	memset(&keytab, 0, sizeof(keytab));
	i = krb5_kt_resolve(ctx, options->keytab, &keytab);
	if (i != 0) {
		warn("error resolving keytab '%s', not verifying TGT",
		     options->keytab);
		return PAM_SERVICE_ERR;
	}

	/* Read the first key from the file. */
	memset(&cursor, 0, sizeof(cursor));
	i = krb5_kt_start_seq_get(ctx, keytab, &cursor);
	if (i != 0) {
		warn("error reading keytab, not verifying TGT");
		return PAM_IGNORE;
	}

	memset(&entry, 0, sizeof(entry));
	i = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
	if (i != 0) {
		warn("error reading keytab, not verifying TGT");
		krb5_kt_end_seq_get(ctx, keytab, &cursor);
		krb5_kt_close(ctx, keytab);
		return PAM_IGNORE;
	}

	/* Get the principal to which the key belongs, for logging purposes. */
	principal = NULL;
	i = krb5_unparse_name(ctx, entry.principal, &principal);
	if (i != 0) {
		warn("internal error parsing principal name, "
		     "not verifying TGT");
		krb5_kt_end_seq_get(ctx, keytab, &cursor);
		krb5_kt_close(ctx, keytab);
		return PAM_SERVICE_ERR;
	}

	/* Close the keytab here.  Even though we're using cursors, the file
	 * handle is stored in the krb5_keytab structure, and it gets
	 * overwritten when the verify_init_creds() call below creates its own
	 * cursor, creating a leak. */
	krb5_kt_end_seq_get(ctx, keytab, &cursor);

	/* Perform the verification checks using the service key. */
	krb5_verify_init_creds_opt_init(&opt);
	i = krb5_verify_init_creds(ctx, creds,
				   entry.principal, keytab,
				   NULL, &opt);

	krb5_kt_close(ctx, keytab);

	/* Log success or failure. */
	if (i == 0) {
		notice("TGT verified using key for '%s'", principal);
		v5_free_unparsed_name(ctx, principal);
		return PAM_SUCCESS;
	} else {
		crit("TGT failed verification using key for '%s'",
		     principal);
		v5_free_unparsed_name(ctx, principal);
		return PAM_AUTH_ERR;
	}
}

int
v5_get_creds(krb5_context ctx,
	     pam_handle_t *pamh,
	     krb5_creds *creds,
	     const char *user,
	     struct _pam_krb5_user_info *userinfo,
	     struct _pam_krb5_options *options,
	     char *service,
	     char *password,
	     krb5_get_init_creds_opt *gic_options,
	     krb5_error_code prompter(krb5_context,
	    			      void *,
				      const char *,
				      const char *,
				      int,
				      krb5_prompt[]),
	     int *result)
{
	int i;
	char realm_service[LINE_MAX];
	char *opt;
	const char *realm;
	struct pam_message message;
	struct _pam_krb5_prompter_data prompter_data;
	krb5_principal service_principal;
	krb5_creds tmpcreds;
	krb5_ccache ccache;

	/* In case we already have creds, get rid of them. */
	krb5_free_cred_contents(ctx, creds);
	memset(creds, 0, sizeof(*creds));

	/* Check some string lengths. */
	if (strchr(userinfo->unparsed_name, '@') != NULL) {
		realm = strchr(userinfo->unparsed_name, '@') + 1;
	} else {
		realm = options->realm;
	}
	if (strlen(service) + 1 +
	    strlen(realm) + 1 +
	    strlen(realm) + 1 >= sizeof(realm_service)) {
		return PAM_SERVICE_ERR;
	}

	/* Cheap hack.  Appends the realm name to a service to generate a
	 * more full service name. */
	if (strchr(service, '/') != NULL) {
		strcpy(realm_service, service);
	} else {
		strcpy(realm_service, service);
		strcat(realm_service, "/");
		strcat(realm_service, realm);
	}
	if (strchr(realm_service, '@') != NULL) {
		strcpy(strchr(realm_service, '@') + 1, realm);
	} else {
		strcat(realm_service, "@");
		strcat(realm_service, realm);
	}
	if (options->debug) {
		debug("authenticating '%s' to '%s'",
		      userinfo->unparsed_name, realm_service);
	}
	/* Get creds. */
	if (options->existing_ticket) {
		/* Try to read the TGT from the existing ccache. */
		i = KRB5_CC_NOTFOUND;
		memset(&service_principal, 0, sizeof(service_principal));
		if (krb5_parse_name(ctx, realm_service,
				    &service_principal) == 0) {
			if (options->debug) {
				debug("attempting to read existing credentials "
				      "from %s", krb5_cc_default_name(ctx));
			}
			memset(&ccache, 0, sizeof(ccache));
			if (krb5_cc_default(ctx, &ccache) == 0) {
				tmpcreds.client = userinfo->principal_name;
				tmpcreds.server = service_principal;
				i = krb5_cc_retrieve_cred(ctx, ccache, 0,
							  &tmpcreds, creds);
				/* FIXME: check if the creds are expired?
				 * What's the right error code if we check, and
				 * they are? */
				memset(&tmpcreds, 0, sizeof(tmpcreds));
				krb5_cc_close(ctx, ccache);
			} else {
				warn("error opening default ccache");
				i = KRB5_CC_NOTFOUND;
			}
			krb5_free_principal(ctx, service_principal);
		} else {
			warn("error parsing TGT principal name (%s) "
			     "(shouldn't happen)", realm_service);
			i = KRB5_REALM_CANT_RESOLVE;
		}
	} else {
		/* Contact the KDC. */
		prompter_data.pamh = pamh;
		prompter_data.previous_password = password;
		prompter_data.options = options;
		prompter_data.userinfo = userinfo;
		if (options->debug && options->debug_sensitive) {
			debug("attempting with password=%s%s%s",
			      password ? "\"" : "",
			      password ? password : "(null)",
			      password ? "\"" : "");
		}
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT
		opt = v5_user_info_subst(ctx, user, userinfo, options,
					 options->pkinit_identity);
		if (opt != NULL) {
			if (strlen(opt) > 0) {
				if (options->debug) {
					debug("resolved pkinit identity to "
					      "\"%s\"", opt);
				}
				krb5_get_init_creds_opt_set_pkinit(ctx,
								   gic_options,
								   userinfo->principal_name,
								   opt,
								   NULL,
#ifdef KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_TAKES_11_ARGS
								   NULL,
								   NULL,
#endif
								   options->pkinit_flags,
								   prompter,
								   &prompter_data,
								   password);
			} else {
				if (options->debug) {
					debug("pkinit identity has no "
					      "contents, ignoring");
				}
			}
			free(opt);
		} else {
			warn("error resolving pkinit identity template \"%s\" ",
			     "to a useful value", options->pkinit_identity);
		}
#endif
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PA
		for (i = 0;
		     (options->preauth_options != NULL) &&
		     (options->preauth_options[i] != NULL);
		     i++) {
			opt = v5_user_info_subst(ctx, user, userinfo, options,
						 options->preauth_options[i]);
			if (opt != NULL) {
				char *val;
				val = strchr(opt, '=');
				if (val != NULL) {
					*val++ = '\0';
					if (options->debug) {
						debug("setting preauth option "
						      "\"%s\" = \"%s\"",
						      opt, val);
					}
					if (krb5_get_init_creds_opt_set_pa(ctx,
									   gic_options,
									   opt,
									   val) != 0) {
						warn("error setting preauth "
						     "option \"%s\"", opt);
					}
				}
				free(opt);
			} else {
				warn("error resolving preauth option \"%s\" ",
				     "to a useful value",
				     options->preauth_options[i]);
			}
		}
#endif
		i = krb5_get_init_creds_password(ctx,
						 creds,
						 userinfo->principal_name,
						 password,
						 prompter,
						 &prompter_data,
						 0,
						 realm_service,
						 gic_options);
	}
	/* Let the caller see the krb5 result code. */
	if (options->debug) {
		debug("krb5_get_init_creds_password(%s) returned %d (%s)",
		      realm_service, i, v5_error_message(i));
	}
	if (result != NULL) {
		*result = i;
	}
	/* Interpret the return code. */
	switch (i) {
	case 0:
		/* Flat-out success.  Validate the TGT if it's actually a TGT,
		 * and if we can. */
		if ((options->validate == 1) &&
		    (strcmp(service, KRB5_TGS_NAME) == 0)) {
			if (options->debug) {
				debug("validating credentials");
			}
			switch (v5_validate(ctx, creds, options)) {
			case PAM_AUTH_ERR:
				return PAM_AUTH_ERR;
				break;
			default:
				break;
			}
		}
		return PAM_SUCCESS;
		break;
	case KRB5KDC_ERR_CLIENT_REVOKED:
		/* There's an entry on the KDC, but it's disabled.  We'll try
		 * to treat that as we would a "principal unknown error". */
		if (options->warn) {
			message.msg = "Error: account is locked.";
			message.msg_style = PAM_TEXT_INFO;
			_pam_krb5_conv_call(pamh, &message, 1, NULL);
		}
		/* fall through */
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	case KRB5KDC_ERR_NAME_EXP:
		/* The user is unknown or a principal has expired. */
		if (options->ignore_unknown_principals) {
			return PAM_IGNORE;
		} else {
			return PAM_USER_UNKNOWN;
		}
		break;
	case KRB5KDC_ERR_KEY_EXP:
		/* The user's key (password) is expired.  We get this error
		 * even if the supplied password is incorrect, so we try to
		 * get a password-changing ticket, which we should be able
		 * to get with an expired password. */
		snprintf(realm_service, sizeof(realm_service),
			 PASSWORD_CHANGE_PRINCIPAL "@%s", realm);
		if (options->debug) {
			debug("key is expired. attempting to verify password "
			      "by obtaining credentials for %s", realm_service);
		}
		prompter_data.pamh = pamh;
		prompter_data.previous_password = password;
		prompter_data.options = options;
		prompter_data.userinfo = userinfo;
		memset(&tmpcreds, 0, sizeof(tmpcreds));
		if (options->debug && options->debug_sensitive) {
			debug("attempting with password=%s%s%s",
			      password ? "\"" : "",
			      password ? password : "(null)",
			      password ? "\"" : "");
		}
		i = krb5_get_init_creds_password(ctx,
						 &tmpcreds,
						 userinfo->principal_name,
						 password,
						 prompter,
						 &prompter_data,
						 0,
						 realm_service,
						 NULL);
		krb5_free_cred_contents(ctx, &tmpcreds);
		switch (i) {
		case 0:
			/* Got password-changing creds, so warn about the
			 * expired password and continue. */
			if (options->warn == 1) {
				message.msg = "Warning: password has expired.";
				message.msg_style = PAM_TEXT_INFO;
				_pam_krb5_conv_call(pamh, &message, 1, NULL);
			}
			return PAM_SUCCESS;
			break;
		}
		return PAM_AUTH_ERR;
		break;
	case EAGAIN:
	case KRB5_REALM_CANT_RESOLVE:
	case KRB5_KDC_UNREACH:
		return PAM_AUTHINFO_UNAVAIL;
	default:
		return PAM_AUTH_ERR;
	}
}

static int
v5_save(krb5_context ctx,
	struct _pam_krb5_stash *stash,
	const char *user,
	struct _pam_krb5_user_info *userinfo,
	struct _pam_krb5_options *options,
	const char **ret_ccname,
	int clone_cc)
{
	char ccname[PATH_MAX];
	krb5_ccache ccache;
	static int counter = 0;

	if (ret_ccname != NULL) {
		*ret_ccname = NULL;
	}

	/* Ensure that we have credentials for saving. */
	if (v5_creds_check_initialized(ctx, &stash->v5creds) != 0) {
		if (options->debug) {
			debug("credentials not initialized");
		}
		return KRB5KRB_ERR_GENERIC;
	}

	/* Derive the ccache name from the supplied template. */
	snprintf(ccname, sizeof(ccname), "MEMORY:_pam_krb5_tmp_s_%s-%d",
		 userinfo->unparsed_name, counter++);
	if (options->debug) {
		debug("saving v5 credentials to '%s' for internal use", ccname);
	}
	/* Create an in-memory structure and then open the file.  One of two
	 * things will happen here.  Either libkrb5 will just use the file, and
	 * we're safer because it wouldn't have used O_EXCL to do so, or it
	 * will nuke the file and reopen it with O_EXCL.  In the latter case,
	 * the descriptor we have will become useless, so we don't actually use
	 * it for anything. */
	if (krb5_cc_resolve(ctx, ccname, &ccache) != 0) {
		warn("error resolving ccache '%s'", ccname);
		return PAM_SERVICE_ERR;
	}
	if (krb5_cc_initialize(ctx, ccache, userinfo->principal_name) != 0) {
		warn("error initializing ccache '%s'", ccname);
		krb5_cc_destroy(ctx, ccache);
		return PAM_SERVICE_ERR;
	}
	if (krb5_cc_store_cred(ctx, ccache, &stash->v5creds) != 0) {
		warn("error storing credentials in ccache '%s'", ccname);
		krb5_cc_destroy(ctx, ccache);
		return PAM_SERVICE_ERR;
	}
	/* If we got to here, we succeeded. */
	krb5_cc_close(ctx, ccache);
	/* Save the new ccache name in the stash, and optionally return it to
	 * the caller. */
	if (_pam_krb5_stash_push_v5(ctx, stash, ccname) == 0) {
		/* Generate a *new* ccache with the same contents as this
		 * one, but for the user's use, and destroy this one. */
		if (clone_cc) {
			_pam_krb5_stash_clone_v5(ctx, stash, options,
						 user, userinfo,
						 userinfo->uid, userinfo->gid);
		}
		if (ret_ccname != NULL) {
			*ret_ccname = stash->v5ccnames->name;
		}
	}
	return PAM_SUCCESS;
}

int
v5_save_for_user(krb5_context ctx,
		 struct _pam_krb5_stash *stash,
		 const char *user,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 const char **ccname)
{
	return v5_save(ctx, stash, user, userinfo, options, ccname, 1);
}

int
v5_save_for_tokens(krb5_context ctx,
		   struct _pam_krb5_stash *stash,
		   const char *user,
		   struct _pam_krb5_user_info *userinfo,
		   struct _pam_krb5_options *options,
		   const char **ccname)
{
	return v5_save(ctx, stash, user, userinfo, options, ccname, 0);
}

int
v5_get_creds_etype(krb5_context ctx,
		   struct _pam_krb5_user_info *userinfo,
		   struct _pam_krb5_options *options,
		   krb5_creds *current_creds, int wanted_etype,
		   krb5_creds **target_creds)
{
	krb5_ccache ccache;
	char ccache_path[PATH_MAX + 6];
	krb5_creds *new_creds, *tmp_creds;
	krb5_error_code i;
	static int counter = 0;

	/* First, nuke anything that's already in the target creds struct. */
	if (*target_creds != NULL) {
		krb5_free_cred_contents(ctx, *target_creds);
		memset(*target_creds, 0, sizeof(krb5_creds));
	}

	/* Ensure that we have credentials. */
	if (v5_creds_check_initialized(ctx, current_creds) != 0) {
		if (options->debug) {
			debug("credentials not initialized");
		}
		return KRB5KRB_ERR_GENERIC;
	}

	/* Check for the simple case -- do we already have such creds? */
	if (v5_creds_get_etype(ctx, current_creds) == wanted_etype) {
		return krb5_copy_creds(ctx, current_creds, target_creds);
	}

	/* Crap.  We have to do things the long way. */
	snprintf(ccache_path, sizeof(ccache_path),
		 "MEMORY:_pam_krb5_tmp_e_%s-%d", userinfo->unparsed_name,
		 counter++);
	ccache = NULL;
	i = krb5_cc_resolve(ctx, ccache_path, &ccache);
	if (i != 0) {
		if (options->debug) {
			debug("error resolving temporary ccache '%s': %s",
			      ccache_path, v5_error_message(i));
		}
		return i;
	}

	i = krb5_cc_initialize(ctx, ccache, userinfo->principal_name);
	if (i != 0) {
		if (options->debug) {
			debug("error initializing temporary ccache: %s",
			      v5_error_message(i));
		}
		krb5_cc_destroy(ctx, ccache);
		return i;
	}

	i = krb5_cc_store_cred(ctx, ccache, current_creds);
	if (i != 0) {
		if (options->debug) {
			debug("error storing credentials in temporary ccache: "
			      "%s", v5_error_message(i));
		}
		krb5_cc_destroy(ctx, ccache);
		return i;
	}

	/* Make a copy of the existing credentials and set the desired etype. */
	tmp_creds = NULL;
	i = krb5_copy_creds(ctx, current_creds, &tmp_creds);
	if (i != 0) {
		if (options->debug) {
			debug("error copying credentials (shouldn't happen)");
		}
		krb5_cc_destroy(ctx, ccache);
		return i;
	}
	v5_creds_set_etype(ctx, tmp_creds, wanted_etype);

	/* Go for it. */
	new_creds = NULL;
	i = krb5_get_credentials(ctx, 0, ccache, tmp_creds, &new_creds);

	if (i != 0) {
		if (options->debug) {
			debug("error obtaining credentials with etype %d using "
			      "existing credentials: %d (%s)",
			      wanted_etype, i, v5_error_message(i));
		}
		krb5_free_creds(ctx, tmp_creds);
		krb5_cc_destroy(ctx, ccache);
		return i;
	}

	krb5_free_creds(ctx, tmp_creds);
	krb5_cc_destroy(ctx, ccache);
	*target_creds = new_creds;
	return i;
}

void
v5_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	   struct _pam_krb5_options *options)
{
	if (stash->v5ccnames != NULL) {
		if (options->debug) {
			debug("removing ccache '%s'",
			      stash->v5ccnames->name);
		}
		if (_pam_krb5_stash_pop_v5(ctx, stash) != 0) {
			warn("error removing ccache '%s'",
			     stash->v5ccnames->name);
		}
	}
}

int
v5_cc_retrieve_match(void)
{
#if defined(KRB5_TC_MATCH_KTYPE)
	return KRB5_TC_MATCH_KTYPE;
#elif defined(KRB5_TC_MATCH_KEYTYPE)
	return KRB5_TC_MATCH_KEYTYPE;
#else
#error "Don't know how to search ccaches!"
#endif
}
