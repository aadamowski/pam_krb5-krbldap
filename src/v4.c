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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"
#include "v4.h"
#include "v5.h"
#include "xstr.h"

#ident "$Id$"

#ifdef USE_KRB4

static int
v4_in_tkt(const char *name, const char *instance, const char *realm)
{
	int i;
	char *vname, *vinstance, *vrealm;

	vname = xstrdup(name);
	if (vname == NULL) {
		return KRB5KRB_ERR_GENERIC;
	}
	vinstance = xstrdup(instance);
	if (vinstance == NULL) {
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}
	vrealm = xstrdup(realm);
	if (vrealm == NULL) {
		xstrfree(vinstance);
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}

#ifdef HAVE_KRB_IN_TKT
	i = krb_in_tkt(vname, vinstance, vrealm);
#elif defined(HAVE_IN_TKT)
	i = in_tkt(vname, vinstance);
#else
#error "Don't know how to initialize v4 TGT for your Kerberos IV implementation!"
#endif
	xstrfree(vrealm);
	xstrfree(vinstance);
	xstrfree(vname);

	return i;
}

static int
v4_save_credentials(const char *sname,
		    const char *sinstance,
		    const char *srealm,
		    unsigned char *session,
		    int lifetime,
		    int kvno,
		    KTEXT ticket,
		    int32_t issue_date)
{
	int i;
	char *vname, *vinstance, *vrealm;

	vname = xstrdup(sname);
	if (vname == NULL) {
		return KRB5KRB_ERR_GENERIC;
	}
	vinstance = xstrdup(sinstance);
	if (vinstance == NULL) {
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}
	vrealm = xstrdup(srealm);
	if (vrealm == NULL) {
		xstrfree(vinstance);
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}

#ifdef HAVE_KRB_SAVE_CREDENTIALS
	i = krb_save_credentials(vname, vinstance, vrealm,
				 session, lifetime, kvno,
				 ticket, issue_date);
#elif defined(HAVE_SAVE_CREDENTIALS)
	i = save_credentials(vname, vinstance, vrealm,
			     session, lifetime, kvno,
			     ticket, issue_date);
#else
#error "Don't know how to save v4 credentials for your Kerberos IV implementation!"
#endif
	xstrfree(vrealm);
	xstrfree(vinstance);
	xstrfree(vname);

	return i;
}

static int
_pam_krb5_v4_init(krb5_context ctx,
		  struct _pam_krb5_stash *stash,
		  struct _pam_krb5_user_info *user,
		  struct _pam_krb5_options *options,
		  char *password,
		  int *result) 
{
	char name[ANAME_SZ + 1], instance[INST_SZ + 1], realm[REALM_SZ + 1];
	char pname[ANAME_SZ + 1], pinstance[INST_SZ + 1];
	char tktfile[PATH_MAX];
	char *saved_tktstring;
	int life, i, fd;

	/* Convert the krb5 version of the principal's name to a v4 principal
	 * name.  This may involve changing "host" to "rcmd" and so on, so let
	 * libkrb5 handle it. */
	memset(name, '\0', sizeof(name));
	memset(instance, '\0', sizeof(instance));
	memset(realm, '\0', sizeof(realm));
	i = krb5_524_conv_principal(ctx, user->principal_name,
				    name, instance, realm);
	if (i != 0) {
		if (result) {
			*result = i;
		}
		return PAM_SERVICE_ERR;
	}
	if (options->debug) {
		debug("converted principal to '%s'[.]'%s'@'%s'",
		      name, instance, realm);
	}

#ifdef HAVE_KRB_TIME_TO_LIFE
	/* Convert the ticket lifetime of the v5 credentials into a v4
	 * lifetime, which is the X coordinate along a curve where Y is the
	 * actual length.  Again, this is magic. */
	life = krb_time_to_life(stash->v5creds.times.starttime,
				stash->v5creds.times.endtime); 
#else
	/* No life_to_time() function means that we have to estimate the
	 * intended lifetime, in 5-minute increments.  We also have a maximum
	 * value to contend with, because the lifetime is expressed in a single
	 * byte. */
	life = stash->v5creds.times.endtime -
	       stash->v5creds.times.starttime;
	life /= (60 * 5);
	if (life > 0xff) {
		life = 0xff;
	}
#endif

	/* Create the ticket file.  One of two things will happen here.  Either
	 * libkrb[4] will just use the file, and we're safer because it
	 * wouldn't have used O_EXCL to do so, or it will nuke the file and
	 * reopen it with O_EXCL.  In the latter case, the descriptor we have
	 * will become useless, so we don't actually use it for anything. */
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%lu_XXXXXX",
		 options->ccache_dir, (unsigned long) user->uid);
	fd = mkstemp(tktfile);
	if (fd == -1) {
		if (result) {
			*result = errno;
		}
		return PAM_SERVICE_ERR;
	}
	if (options->debug) {
		debug("preparing to place v4 credentials in '%s'", tktfile);
	}
	/* Save the old default ticket file name, and set the default to use
	 * our just-created empty file. */
	saved_tktstring = xstrdup(tkt_string());
	krb_set_tkt_string(tktfile);
	/* Get the initial credentials. */
	i = krb_get_pw_in_tkt(name, instance, realm,
			      KRB5_TGS_NAME, realm,
			      life, password);
	if (result) {
		*result = i;
	}
	/* Restore the original default ticket file name. */
	krb_set_tkt_string(saved_tktstring);
	xstrfree(saved_tktstring);
	saved_tktstring = NULL;
	/* If we got credentials, read them from the file, and then remove the
	 * file. */
	if (i == 0) {
		i = tf_init(tktfile, R_TKT_FIL);
		if (i == 0) {
			i = tf_get_pname(pname);
			if (i == 0) {
				i = tf_get_pinst(pinstance);
				if (i == 0) {
					i = tf_get_cred(&stash->v4creds);
					if (i == 0) {
						tf_close();
						unlink(tktfile);
						close(fd);
						return PAM_SUCCESS;
					} else {
						warn("error reading creds "
						     "from '%s': %d (%s)",
						     tktfile,
						     i, v5_error_message(i));
					}
				} else {
					warn("error reading instance from '%s'"
					     ": %d (%s)",
					     tktfile, i, v5_error_message(i));
				}
			} else {
				warn("error reading principal name from '%s'"
				     ": %d (%s)",
				     tktfile, i, v5_error_message(i));
			}
			tf_close();
		} else {
			warn("error opening '%s' for reading: %s",
			     tktfile, strerror(errno));
		}
	}
	unlink(tktfile);
	close(fd);
	return PAM_AUTH_ERR;
}

int
v4_save(krb5_context ctx,
	struct _pam_krb5_stash *stash,
	struct _pam_krb5_user_info *userinfo,
	struct _pam_krb5_options *options,
	uid_t uid, gid_t gid,
	char **ccname)
{
	char name[ANAME_SZ + 1], instance[INST_SZ + 1], realm[REALM_SZ + 1];
	char tktfile[PATH_MAX];
	char *saved_tktstring;
	int i, fd;

	if (ccname != NULL) {
		*ccname = NULL;
	}

	/* Convert the v5 principal name into v4 notation. */
	memset(name, '\0', sizeof(name));
	memset(instance, '\0', sizeof(instance));
	memset(realm, '\0', sizeof(realm));
	i = krb5_524_conv_principal(ctx, userinfo->principal_name,
				    name, instance, realm);
	if (i != 0) {
		warn("error converting %s to a Kerberos IV principal "
		     "(shouldn't happen)", userinfo->unparsed_name);
		return PAM_SERVICE_ERR;
	}

	/* Create a new ticket file. */
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%lu_XXXXXX",
		 options->ccache_dir, (unsigned long) userinfo->uid);
	fd = mkstemp(tktfile);
	if (fd == -1) {
		warn("error creating unique Kerberos IV ticket file "
		     "(shouldn't happen)");
		return PAM_SERVICE_ERR;
	}

	/* Open the ticket file. */
	saved_tktstring = xstrdup(tkt_string());
	krb_set_tkt_string(tktfile);
	if (tf_init(tktfile, W_TKT_FIL) != 0) {
		warn("error opening ticket file '%s': %s",
		     tktfile, strerror(errno));
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Store the user's name. */
	if (v4_in_tkt(name, instance, realm) != 0) {
		warn("error initializing ticket file '%s'", tktfile);
		tf_close();
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Store the v4 credentials. */
	if (v4_save_credentials(KRB5_TGS_NAME, realm, realm,
				stash->v4creds.session,
				stash->v4creds.lifetime,
				stash->v4creds.kvno,
				&stash->v4creds.ticket_st,
				stash->v4creds.issue_date) != 0) {
		warn("error saving tickets to '%s'", tktfile);
		tf_close();
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Close the new file. */
	tf_close();
	xstrfree(saved_tktstring);
	close(fd);

	/* Destroy any old ticket files we might have.  One per customer. */
	v4_destroy(ctx, stash, options);
	stash->v4file = xstrdup(tktfile);

	/* Generate a *new* ticket file with the same contents as this one. */
	_pam_krb5_stash_clone_v4(stash, userinfo->uid, userinfo->gid);
	krb_set_tkt_string(stash->v4file);
	if (ccname != NULL) {
		*ccname = stash->v4file;
	}
	return PAM_SUCCESS;
}

void
v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	   struct _pam_krb5_options *options)
{
	if (stash->v4file != NULL) {
		if (options->debug) {
			debug("removing ticket file '%s'", stash->v4file);
		}
		if (_pam_krb5_stash_clean_v4(stash) != 0) {
			warn("error removing ticket file '%s'", stash->v4file);
		}
	}
}

int
v4_get_creds(krb5_context ctx,
	     pam_handle_t *pamh,
	     struct _pam_krb5_stash *stash,
	     struct _pam_krb5_user_info *userinfo,
	     struct _pam_krb5_options *options,
	     char *password,
	     int *result)
{
	int i;
#if defined(HAVE_KRB5_524_CONVERT_CREDS) || \
    defined(HAVE_KRB524_CONVERT_CREDS_KDC)
	krb5_creds *v4_compat_creds, *in_creds;

	v4_compat_creds = NULL;
	if (options->debug) {
		debug("obtaining v4-compatible key");
	}
	/* We need a DES-CBC-CRC v5 credential to convert to a proper v4
	 * credential. */
	i = v5_get_creds_etype(ctx, userinfo, options, &stash->v5creds,
			       ENCTYPE_DES_CBC_CRC, &v4_compat_creds);
	if (i == 0) {
		if (options->debug) {
			debug("obtained des-cbc-crc v5 creds");
		}
		in_creds = v4_compat_creds;
	} else {
		if (options->debug) {
			debug("failed to obtain des-cbc-crc v5 creds: %d (%s)",
			      i, error_message(i));
		}
		in_creds = NULL;
		if (v5_creds_check_initialized(ctx, &stash->v5creds) == 0) {
			krb5_copy_creds(ctx, &stash->v5creds, &in_creds);
		}
	}
#ifdef HAVE_KRB5_524_CONVERT_CREDS
	if (options->debug) {
		debug("converting v5 creds to v4 creds (etype = %d)",
		      in_creds ? v5_creds_get_etype(ctx, in_creds) : 0);
	}
	if ((in_creds != NULL) &&
	    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
		i = krb5_524_convert_creds(ctx, in_creds, &stash->v4creds);
		if (i == 0) {
			if (options->debug) {
				debug("conversion succeeded");
			}
			stash->v4present = 1;
			if (result) {
				*result = i;
			}
			krb5_free_creds(ctx, in_creds);
			return PAM_SUCCESS;
		} else {
			if (options->debug) {
				debug("conversion failed: %d (%s)",
				      i, v5_error_message(i));
			}
		}
	}
#endif
#ifdef HAVE_KRB524_CONVERT_CREDS_KDC
	if (options->debug) {
		debug("converting v5 creds to v4 creds (etype = %d)",
		      in_creds ? v5_creds_get_etype(ctx, in_creds) : 0);
	}
	if ((in_creds != NULL) &&
	    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
		i = krb524_convert_creds_kdc(ctx, in_creds, &stash->v4creds);
		if (i == 0) {
			if (options->debug) {
				debug("conversion succeeded");
			}
			stash->v4present = 1;
			if (result) {
				*result = i;
			}
			krb5_free_creds(ctx, in_creds);
			return PAM_SUCCESS;
		} else {
			if (options->debug) {
				debug("conversion failed: %d (%s)",
				      i, v5_error_message(i));
			}
		}
	}
#endif
	if ((in_creds != NULL) &&
	    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
		krb5_free_creds(ctx, in_creds);
	}
#endif
	if (options->debug) {
		debug("obtaining initial v4 creds");
	}
	i = _pam_krb5_v4_init(ctx, stash, userinfo, options,
			      password, result);
	if (i == PAM_SUCCESS) {
		if (options->debug) {
			debug("initial v4 creds obtained");
		}
		stash->v4present = 1;
		return PAM_SUCCESS;
	}
	if (options->debug) {
		debug("could not obtain initial v4 creds: %d (%s)",
		      i, v5_error_message(i));
	}
	return PAM_AUTH_ERR;
}

#else

int
v4_save(krb5_context ctx,
	struct _pam_krb5_stash *stash,
	struct _pam_krb5_user_info *userinfo,
	struct _pam_krb5_options *options,
	uid_t uid, gid_t gid,
	const char **ccname)
{
	if (ccname != NULL) {
		*ccname = NULL;
	}
	return PAM_SERVICE_ERR;
}

void
v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	   struct _pam_krb5_options *options)
{
	return;
}

#endif
