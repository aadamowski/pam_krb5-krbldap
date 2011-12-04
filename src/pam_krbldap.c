/*
 * Copyright 2011, Aleksander Adamowski
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

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#endif

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Including libkrb5 private headers for the need of its message encoding
 * functions. Unfortunately, this risks breakage with future releases of krb5 
 * and internal changes generally aren't written up in krb5 release notes.
 * NOTE: because of this, the pam_krb5 module must now be placed inside
 * krb5 sources (e.g. krb5/src/pam_krb5) so that it has access to its private
 * headers. */
#define KRB5_PRIVATE 1
#include "k5-int.h"
/* Other private krb5 headers START */
#include "init_creds_ctx.h"
/* Other private krb5 headers END */

/*#include KRB5_H*/

#include <stdio.h>

#include <lber.h>
#include <ldap.h>

#include "conv.h"
#include "init.h"
#include "initopts.h"
#include "items.h"
#include "kuserok.h"
#include "log.h"
#include "options.h"
#include "prompter.h"
#include "pam_krbldap.h"

#define MAX_IN_TKT_LOOPS 16

/* BEGIN blatant copy from auth.c */

/* TODO: maybe we can use unmodified extern pam_sm_authenticate from auth.c
 *  but supply it with local substitute functions from around here? */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
        int argc, PAM_KRB5_MAYBE_CONST char **argv) {
    PAM_KRB5_MAYBE_CONST char *user;
    krb5_context ctx;
    struct _pam_krb5_options *options;
    struct _pam_krb5_user_info *userinfo;
    struct _pam_krb5_stash *stash;
    krb5_get_init_creds_opt *gic_options;
    int i, retval, use_third_pass, prompted, prompt_result;
    char *first_pass, *second_pass;

    printf("Now in krbldap.\n");

    /* Initialize Kerberos. */
    if (_pam_krb5_init_ctx(&ctx, argc, argv) != 0) {
        warn("error initializing Kerberos");
        return PAM_SERVICE_ERR;
    }

    /* Get the user's name. */
    i = pam_get_user(pamh, &user, NULL);
    if ((i != PAM_SUCCESS) || (user == NULL)) {
        warn("could not identify user name");
        krb5_free_context(ctx);
        return i;
    }

    /* Read our options. */
    i = v5_alloc_get_init_creds_opt(ctx, &gic_options);
    if (i != 0) {
        warn("error initializing options (shouldn't happen)");
        krb5_free_context(ctx);
        return PAM_SERVICE_ERR;
    }
    options = _pam_krb5_options_init(pamh, argc, argv, ctx);
    if (options == NULL) {
        warn("error parsing options (shouldn't happen)");
        v5_free_get_init_creds_opt(ctx, gic_options);
        krb5_free_context(ctx);
        return PAM_SERVICE_ERR;
    }
    if (options->debug) {
        debug("called to authenticate '%s', realm '%s'", user,
                options->realm);
    }
    _pam_krb5_set_init_opts(ctx, gic_options, options);

    /* Prompt for the password, as we might need to. */
    prompted = 0;
    prompt_result = PAM_ABORT;
    second_pass = NULL;
    if (options->use_second_pass) {
        first_pass = NULL;
        i = _pam_krb5_get_item_text(pamh, PAM_AUTHTOK, &first_pass);
        if ((i != PAM_SUCCESS) || (first_pass == NULL)) {
            /* Nobody's asked for a password yet. */
            prompt_result = _pam_krb5_prompt_for(pamh,
                    Y_("Password: "),
                    &second_pass);
            prompted = 1;
        }
    }

    /* Get information about the user and the user's principal name. */
    userinfo = _pam_krb5_user_info_init(ctx, user, options);
    if (userinfo == NULL) {
        if (options->ignore_unknown_principals) {
            retval = PAM_IGNORE;
        } else {
            warn("error getting information about '%s'", user);
            retval = PAM_USER_UNKNOWN;
        }
        if (prompted && (prompt_result == 0) && (second_pass != NULL)) {
            if (options->debug) {
                debug("saving newly-entered "
                        "password for use by "
                        "other modules");
            }
            pam_set_item(pamh, PAM_AUTHTOK, second_pass);
        }
        /* Clean up and return. */
        _pam_krb5_options_free(pamh, ctx, options);
        v5_free_get_init_creds_opt(ctx, gic_options);
        krb5_free_context(ctx);
        return retval;
    }
    if (options->debug) {
        debug("authenticating '%s'", userinfo->unparsed_name);
    }

    /* Check the minimum UID argument. */
    if ((options->user_check) &&
            (options->minimum_uid != (uid_t) - 1) &&
            (userinfo->uid < options->minimum_uid)) {
        if (options->debug) {
            debug("ignoring '%s' -- uid below minimum = %lu", user,
                    (unsigned long) options->minimum_uid);
        }
        _pam_krb5_user_info_free(ctx, userinfo);
        if (prompted && (prompt_result == 0) && (second_pass != NULL)) {
            if (options->debug) {
                debug("saving newly-entered "
                        "password for use by "
                        "other modules");
            }
            pam_set_item(pamh, PAM_AUTHTOK, second_pass);
        }
        _pam_krb5_options_free(pamh, ctx, options);
        v5_free_get_init_creds_opt(ctx, gic_options);
        krb5_free_context(ctx);
        return PAM_IGNORE;
    }

    /* Get the stash for this user. */
    stash = _pam_krb5_stash_get(pamh, user, userinfo, options);
    if (stash == NULL) {
        warn("error retrieving stash for '%s' (shouldn't happen)",
                user);
        _pam_krb5_user_info_free(ctx, userinfo);
        if (prompted && (prompt_result == 0) && (second_pass != NULL)) {
            if (options->debug) {
                debug("saving newly-entered "
                        "password for use by "
                        "other modules");
            }
            pam_set_item(pamh, PAM_AUTHTOK, second_pass);
        }
        _pam_krb5_options_free(pamh, ctx, options);
        v5_free_get_init_creds_opt(ctx, gic_options);
        krb5_free_context(ctx);
        return PAM_SERVICE_ERR;
    }

    /* If we've been called before, then the stash is more or less stale,
     * so reset things for applications which call pam_authenticate() more
     * than once with the same library context. */
    stash->v5attempted = 0;

    retval = PAM_AUTH_ERR;

    /* If we're configured to use an existing ccache, try that. */
    if ((retval != PAM_SUCCESS) && (options->existing_ticket)) {
        if (options->debug) {
            debug("trying existing credentials for '%s'", user);
        }
        retval = krbldap_get_creds(ctx, pamh,
                &stash->v5creds, user, userinfo,
                options,
                KRB5_TGS_NAME,
                NULL,
                gic_options,
                _pam_krb5_always_fail_prompter,
                &stash->v5expired,
                &stash->v5result);
        stash->v5external = 0;
        stash->v5attempted = 1;
        if (options->debug) {
            debug("got result %d (%s)", stash->v5result,
                    v5_error_message(stash->v5result));
        }
    }

    /* Ideally we're only going to let libkrb5 ask questions once, and
     * after that we intend to lie to it. */
    use_third_pass = options->use_third_pass;

    /* Try with the stored password, if we've been told to use just that
     * value. */
    first_pass = NULL;
    if ((retval != PAM_SUCCESS) && options->use_first_pass) {
        i = _pam_krb5_get_item_text(pamh, PAM_AUTHTOK, &first_pass);
        if ((i == PAM_SUCCESS) &&
                (flags & PAM_DISALLOW_NULL_AUTHTOK) &&
                (first_pass != NULL) &&
                (strlen(first_pass) == 0)) {
            warn("disallowing NULL authtok for '%s'", user);
            retval = PAM_AUTH_ERR;
            i = PAM_AUTH_ERR;
        }
        if ((i == PAM_SUCCESS) &&
                (first_pass != NULL) &&
                (strlen(first_pass) > 0)) {
            if (options->debug) {
                if (use_third_pass) {
                    debug("trying previously-entered "
                            "password for '%s', allowing "
                            "libkrb5 to prompt for more",
                            user);
                } else {
                    debug("trying previously-entered "
                            "password for '%s'", user);
                }
            }
            retval = krbldap_get_creds(ctx, pamh,
                    &stash->v5creds, user, userinfo,
                    options,
                    KRB5_TGS_NAME,
                    first_pass,
                    gic_options,
                    use_third_pass ?
                    _pam_krb5_normal_prompter :
                    _pam_krb5_previous_prompter,
                    &stash->v5expired,
                    &stash->v5result);
            use_third_pass = 0;
            stash->v5external = 0;
            stash->v5attempted = 1;
            if (options->debug) {
                debug("got result %d (%s)", stash->v5result,
                        v5_error_message(stash->v5result));
            }
        }
        if ((retval == PAM_SUCCESS) &&
                ((options->v4 == 1) || (options->v4_for_afs == 1))) {
            v4_get_creds(ctx, pamh, stash, userinfo, options,
                    first_pass, &i);
            if ((i != 0) && (options->debug)) {
                debug("error obtaining v4 creds: %d (%s)",
                        i, v5_error_message(i));
            }
            if (stash->v4present &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                v4_save_for_tokens(ctx, stash, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v4_destroy(ctx, stash, options);
                v5_destroy(ctx, stash, options);
            }
        } else {
            if ((retval == PAM_SUCCESS) &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v5_destroy(ctx, stash, options);
            }
        }
    }

    /* If that didn't work, and we're allowed to ask for a new password, do
     * so in preparation for another attempt. */
    if ((retval != PAM_SUCCESS) &&
            (retval != PAM_USER_UNKNOWN) &&
            options->use_second_pass) {
        /* The "second_pass" variable already contains a value if we
         * asked for one. */
        if (!prompted) {
            prompt_result = _pam_krb5_prompt_for(pamh,
                    Y_("Password: "),
                    &second_pass);
            prompted = 1;
        }
        i = prompt_result;
        if ((i == PAM_SUCCESS) &&
                (flags & PAM_DISALLOW_NULL_AUTHTOK) &&
                (second_pass != NULL) &&
                (strlen(second_pass) == 0)) {
            warn("disallowing NULL authtok for '%s'", user);
            retval = PAM_AUTH_ERR;
            i = PAM_AUTH_ERR;
        }
        if ((i == PAM_SUCCESS) &&
                (second_pass != NULL) &&
                (strlen(second_pass) > 0)) {
            /* Save the password for the next module. */
            if (options->debug) {
                debug("saving newly-entered "
                        "password for use by "
                        "other modules");
            }
            pam_set_item(pamh, PAM_AUTHTOK, second_pass);
            if (options->debug) {
                if (use_third_pass) {
                    debug("trying newly-entered "
                            "password for '%s', allowing "
                            "libkrb5 to prompt for more",
                            user);
                } else {
                    debug("trying newly-entered "
                            "password for '%s'", user);
                }
            }
            retval = krbldap_get_creds(ctx, pamh,
                    &stash->v5creds, user, userinfo,
                    options,
                    KRB5_TGS_NAME,
                    second_pass,
                    gic_options,
                    use_third_pass ?
                    _pam_krb5_normal_prompter :
                    _pam_krb5_always_fail_prompter,
                    &stash->v5expired,
                    &stash->v5result);
            use_third_pass = 0;
            stash->v5external = 0;
            stash->v5attempted = 1;
            if (options->debug) {
                debug("got result %d (%s)", stash->v5result,
                        v5_error_message(stash->v5result));
            }
        }
        if ((retval == PAM_SUCCESS) &&
                ((options->v4 == 1) || (options->v4_for_afs == 1))) {
            v4_get_creds(ctx, pamh, stash, userinfo, options,
                    second_pass, &i);
            if ((i != 0) && (options->debug)) {
                debug("error obtaining v4 creds: %d (%s)",
                        i, v5_error_message(i));
            }
            if (stash->v4present &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                v4_save_for_tokens(ctx, stash, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v4_destroy(ctx, stash, options);
                v5_destroy(ctx, stash, options);
            }
        } else {
            if ((retval == PAM_SUCCESS) &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v5_destroy(ctx, stash, options);
            }
        }
    }

    /* If we didn't use the first password (because it wasn't set), and we
     * didn't ask for a password (due to the "no_initial_prompt" flag,
     * probably), and we can let libkrb5 ask questions (no
     * "no_subsequent_prompt"), then let libkrb5 have another go. */
    if ((retval != PAM_SUCCESS) &&
            (retval != PAM_USER_UNKNOWN) &&
            use_third_pass) {
        if (options->debug) {
            debug("not using an entered password for '%s', "
                    "allowing libkrb5 to prompt for more", user);
        }
        retval = krbldap_get_creds(ctx, pamh,
                &stash->v5creds, user, userinfo,
                options,
                KRB5_TGS_NAME,
                NULL,
                gic_options,
                options->permit_password_callback ?
                _pam_krb5_always_prompter :
                _pam_krb5_normal_prompter,
                &stash->v5expired,
                &stash->v5result);
        stash->v5external = 0;
        stash->v5attempted = 1;
        if (options->debug) {
            debug("got result %d (%s)", stash->v5result,
                    v5_error_message(stash->v5result));
        }
        if ((retval == PAM_SUCCESS) &&
                ((options->v4 == 1) || (options->v4_for_afs == 1))) {
            v4_get_creds(ctx, pamh, stash, userinfo, options,
                    second_pass, &i);
            if ((i != 0) && (options->debug)) {
                debug("error obtaining v4 creds: %d (%s)",
                        i, v5_error_message(i));
            }
            if (stash->v4present &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                v4_save_for_tokens(ctx, stash, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v4_destroy(ctx, stash, options);
                v5_destroy(ctx, stash, options);
            }
        } else {
            if ((retval == PAM_SUCCESS) &&
                    (options->ignore_afs == 0) &&
                    (options->tokens == 1) &&
                    tokens_useful()) {
                v5_save_for_tokens(ctx, stash, user, userinfo,
                        options, NULL);
                tokens_obtain(ctx, stash, options, userinfo, 1);
                v5_destroy(ctx, stash, options);
            }
        }
    }

    /* If we got this far, check the target user's .k5login file. */
    if ((retval == PAM_SUCCESS) && options->user_check &&
            (options->ignore_k5login == 0)) {
        if (_pam_krb5_kuserok(ctx, stash, options, userinfo, user,
                userinfo->uid, userinfo->gid) != TRUE) {
            notice("account checks fail for '%s': user disallowed "
                    "by .k5login file for '%s'",
                    userinfo->unparsed_name, user);
            retval = PAM_PERM_DENIED;
        } else {
            if (options->debug) {
                debug("'%s' passes .k5login check for '%s'",
                        userinfo->unparsed_name, user);
            }
        }
    }

    /* Log the authentication status, optionally saving the credentials in
     * a piece of shared memory. */
    if (retval == PAM_SUCCESS) {
        if (options->use_shmem) {
            _pam_krb5_stash_shm_write(pamh, stash, options,
                    user, userinfo);
        }
        notice("authentication succeeds for '%s' (%s)", user,
                userinfo->unparsed_name);
    } else {
        if ((retval == PAM_USER_UNKNOWN) &&
                options->ignore_unknown_principals) {
            retval = PAM_IGNORE;
        } else {
            notice("authentication fails for '%s' (%s): %s (%s)",
                    user,
                    userinfo->unparsed_name,
                    pam_strerror(pamh, retval),
                    v5_error_message(stash->v5result));
        }
    }

    /* Clean up. */
    if (options->debug) {
        debug("pam_authenticate returning %d (%s)", retval,
                pam_strerror(pamh, retval));
    }
    v5_free_get_init_creds_opt(ctx, gic_options);
    _pam_krb5_options_free(pamh, ctx, options);
    _pam_krb5_user_info_free(ctx, userinfo);
    krb5_free_context(ctx);

    return retval;

}

static int
krbldap_validate_using_ccache(krb5_context ctx, krb5_creds *creds,
        struct _pam_krb5_user_info *userinfo,
        const struct _pam_krb5_options *options) {
    krb5_ccache ccache;
    krb5_ticket *ticket;
    krb5_creds mcreds, *ocreds, *ucreds;
    krb5_auth_context auth_con;
    krb5_data req;
    krb5_flags flags;
    krb5_error_code ret;
    char ccname[PATH_MAX];
    static int counter = 0;

    if (options->debug) {
        debug("attempting to verify credentials using user-to-user "
                "auth to ccache '%s'", krb5_cc_default_name(ctx));
    }

    /* Open the default ccache and see if it has creds that look like the
     * ones we're checking, but which use a different key (i.e., don't
     * bother if the creds are the ones we have already). */
    ccache = NULL;
    ret = krb5_cc_default(ctx, &ccache);
    if (ret != 0) {
        warn("error opening default ccache: %s", error_message(ret));
        return PAM_SERVICE_ERR;
    }

    memset(&mcreds, 0, sizeof (mcreds));
    mcreds.client = creds->client;
    mcreds.server = creds->server;
    ocreds = NULL;
    ret = krb5_get_credentials(ctx, KRB5_GC_CACHED, ccache,
            &mcreds, &ocreds);
    if (ret != 0) {
        warn("error getting cached creds for the same client/server "
                "pair: %s", error_message(ret));
        krb5_cc_close(ctx, ccache);
        return PAM_SERVICE_ERR;
    }
    if (options->debug) {
        debug("found previously-obtained credentials in ccache");
    }
    if ((v5_creds_get_etype(creds) == v5_creds_get_etype(ocreds)) &&
            (v5_creds_key_length(creds) == v5_creds_key_length(ocreds)) &&
            (memcmp(v5_creds_key_contents(creds),
            v5_creds_key_contents(ocreds),
            v5_creds_key_length(creds)) == 0)) {
        warn("internal error - previously-obtained credentials have "
                "the same key as the ones we're attempting to verify");
        krb5_free_creds(ctx, ocreds);
        krb5_cc_close(ctx, ccache);
        return PAM_SERVICE_ERR;
    }
    krb5_cc_close(ctx, ccache);

    /* Create a temporary ccache to hold the creds we're validating and the
     * user-to-user creds we'll be obtaining to validate them. */
    snprintf(ccname, sizeof (ccname), "MEMORY:_pam_krb5_val_s_%s-%d",
            userinfo->unparsed_name, counter++);
    ccache = NULL;
    ret = krb5_cc_resolve(ctx, ccname, &ccache);
    if (ret != 0) {
        warn("internal error creating in-memory ccache: %s",
                error_message(ret));
        krb5_free_creds(ctx, ocreds);
        return PAM_SERVICE_ERR;
    }
    ret = krb5_cc_initialize(ctx, ccache, creds->client);
    if (ret != 0) {
        warn("internal error initializing in-memory ccache: %s",
                error_message(ret));
        krb5_cc_destroy(ctx, ccache);
        krb5_free_creds(ctx, ocreds);
        return PAM_SERVICE_ERR;
    }
    ret = krb5_cc_store_cred(ctx, ccache, creds);
    if (ret != 0) {
        warn("internal error storing creds to in-memory ccache: %s",
                error_message(ret));
        krb5_cc_destroy(ctx, ccache);
        krb5_free_creds(ctx, ocreds);
        return PAM_SERVICE_ERR;
    }

    /* Go get the user-to-user creds for use in authenticating to the
     * holder of the previously-obtained TGT. */
    memset(&mcreds, 0, sizeof (mcreds));
    mcreds.client = creds->client;
    mcreds.server = creds->client;
    mcreds.second_ticket = ocreds->ticket;
    ucreds = NULL;
    ret = krb5_get_credentials(ctx, KRB5_GC_USER_USER, ccache,
            &mcreds, &ucreds);
    if (ret != 0) {
        warn("error obtaining user-to-user creds to '%s': %s",
                userinfo->unparsed_name, error_message(ret));
        notice("TGT failed verification using previously-obtained "
                "credentials in '%s': %s", krb5_cc_default_name(ctx),
                error_message(ret));
        krb5_cc_destroy(ctx, ccache);
        krb5_free_creds(ctx, ocreds);
        return PAM_AUTH_ERR;
    }
    krb5_cc_destroy(ctx, ccache);

    /* Create an auth context and use it to generate a user-to-user auth
     * request to the old TGT. */
    memset(&auth_con, 0, sizeof (auth_con));
    ret = krb5_auth_con_init(ctx, &auth_con);
    if (ret != 0) {
        warn("error initializing auth context: %s",
                error_message(ret));
        krb5_free_creds(ctx, ucreds);
        krb5_free_creds(ctx, ocreds);
        return PAM_SERVICE_ERR;
    }
    if (options->debug) {
        debug("creating user-to-user authentication request to '%s'",
                userinfo->unparsed_name);
    }
    memset(&req, 0, sizeof (req));
    ret = krb5_mk_req_extended(ctx, &auth_con, AP_OPTS_USE_SESSION_KEY,
            NULL, ucreds, &req);
    if (ret != 0) {
        warn("error generating user-to-user AP request to '%s': %s",
                userinfo->unparsed_name, error_message(ret));
        notice("TGT failed verification using previously-obtained "
                "credentials in '%s': %s", krb5_cc_default_name(ctx),
                error_message(ret));
        krb5_auth_con_free(ctx, auth_con);
        krb5_free_creds(ctx, ucreds);
        krb5_free_creds(ctx, ocreds);
        return PAM_AUTH_ERR;
    }
    krb5_free_creds(ctx, ucreds);
    krb5_auth_con_free(ctx, auth_con);

    /* Create an auth context and use it to "receive" the user-to-user
     * auth request using the session key from the previously-obtained
     * credentials. */
    ret = krb5_auth_con_init(ctx, &auth_con);
    if (ret != 0) {
        warn("error initializing auth context: %s",
                error_message(ret));
        krb5_free_data_contents(ctx, &req);
        krb5_free_creds(ctx, ocreds);
        return PAM_SERVICE_ERR;
    }
    ret = v5_auth_con_setuserkey(ctx, auth_con,
            v5_creds_get_key(ocreds));
    krb5_free_creds(ctx, ocreds);
    if (ret != 0) {
        warn("error setting up to receive user-to-user AP request: %s",
                error_message(ret));
        krb5_free_data_contents(ctx, &req);
        krb5_auth_con_free(ctx, auth_con);
        return PAM_SERVICE_ERR;
    }
    if (options->debug) {
        debug("receiving user-to-user authentication request");
    }
    ticket = NULL;
    ret = krb5_rd_req(ctx, &auth_con, &req, NULL, NULL, &flags, &ticket);
    krb5_free_data_contents(ctx, &req);
    if (ret != 0) {
        warn("error receiving user-to-user AP request: %s",
                error_message(ret));
        notice("TGT failed verification using previously-obtained "
                "credentials in '%s': %s", krb5_cc_default_name(ctx),
                error_message(ret));
        krb5_auth_con_free(ctx, auth_con);
        return PAM_AUTH_ERR;
    }
    if (options->debug) {
        debug("checking that the client and server names still match");
    }
    if (krb5_principal_compare(ctx, v5_ticket_get_client(ticket),
            creds->client) == 0) {
        warn("client in user-to-user request was changed");
        notice("TGT failed verification using previously-obtained "
                "credentials in '%s': client name mismatch",
                krb5_cc_default_name(ctx));
        krb5_free_ticket(ctx, ticket);
        krb5_auth_con_free(ctx, auth_con);
        return PAM_AUTH_ERR;
    }
    if (krb5_principal_compare(ctx, ticket->server, creds->client) == 0) {
        warn("server in user-to-user request was changed");
        notice("TGT failed verification using previously-obtained "
                "credentials in '%s': server name mismatch",
                krb5_cc_default_name(ctx));
        krb5_free_ticket(ctx, ticket);
        krb5_auth_con_free(ctx, auth_con);
        return PAM_AUTH_ERR;
    }

    krb5_free_ticket(ctx, ticket);
    krb5_auth_con_free(ctx, auth_con);
    notice("TGT verified using previously-obtained credentials in '%s'",
            krb5_cc_default_name(ctx));
    return PAM_SUCCESS;
}

/* Select the principal name of the service to use when validating the creds in
 * question. */
static int
krbldap_select_keytab_service(krb5_context ctx, krb5_creds *creds,
        const char *ktname,
        krb5_principal *service) {
    krb5_principal host, princ;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    int i, score;

    *service = NULL;

    /* Figure out what the local host service is named -- we're mainly
     * interested in the second component, which is the local hostname. */
    host = NULL;
    i = krb5_sname_to_principal(ctx, NULL, "host", KRB5_NT_SRV_HST, &host);
    if (i != 0) {
        crit("error guessing name of local host principal");
        return PAM_SERVICE_ERR;
    }

    /* Open the keytab. */
    memset(&keytab, 0, sizeof (keytab));
    if (ktname != NULL) {
        i = krb5_kt_resolve(ctx, ktname, &keytab);
    } else {
        i = krb5_kt_default(ctx, &keytab);
    }
    if (i != 0) {
        if (ktname != NULL) {
            warn("error resolving keytab '%s'", ktname);
        } else {
            warn("error resolving default keytab");
        }
        krb5_free_principal(ctx, host);
        return PAM_SERVICE_ERR;
    }

    /* Set up to walk the keytab. */
    memset(&cursor, 0, sizeof (cursor));
    i = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (i != 0) {
        if (ktname != NULL) {
            warn("error reading keytab '%s'", ktname);
        } else {
            warn("error reading default keytab");
        }
        krb5_kt_close(ctx, keytab);
        krb5_free_principal(ctx, host);
        return PAM_SERVICE_ERR;
    }

    /* Walk the keytab, looking for a good service key.  Prefer a "host" in
     * the client's realm, or a (hopefully) host-based service in the
     * client's realm (even better, if the instance matches the local
     * host's name), or anything from the client's realm, but try the first
     * one if we don't find a suitable host key.  If we're being called
     * from a non-"host" service, hopefully this will let us try to do
     * validation using that service's keytab.  */
    princ = NULL;
    score = 0;
    while ((i = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
        /* First entry? */
        if (princ == NULL) {
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
        }
        /* Better entry (anything in the client's realm)? */
        if ((score < 1) &&
                krb5_realm_compare(ctx, entry.principal, creds->client)) {
            if (princ != NULL) {
                krb5_free_principal(ctx, princ);
            }
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
            score = 1;
        }
        /* Even better entry (hopefully a host-based service in the
         * client's realm)? */
        if ((score < 2) &&
                (v5_princ_component_count(entry.principal) == 2) &&
                krb5_realm_compare(ctx, entry.principal, creds->client)) {
            if (princ != NULL) {
                krb5_free_principal(ctx, princ);
            }
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
            score = 2;
        }
        /* Better entry ("host" with what should be a hostname as the
         * instance, in the client's realm)? */
        if ((score < 3) &&
                (v5_princ_component_count(entry.principal) == 2) &&
                krb5_realm_compare(ctx, entry.principal, creds->client) &&
                (v5_princ_component_length(entry.principal, 0) == 4) &&
                (memcmp(v5_princ_component_contents(entry.principal, 0),
                "host", 4) == 0)) {
            if (princ != NULL) {
                krb5_free_principal(ctx, princ);
            }
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
            score = 3;
        }
        /* Better entry (a service with the local hostname as the
         * instance, in the client's realm)? */
        if ((score < 4) &&
                (host != NULL) &&
                (v5_princ_component_count(entry.principal) == 2) &&
                krb5_realm_compare(ctx, entry.principal, creds->client) &&
                (v5_princ_component_length(entry.principal, 1) ==
                v5_princ_component_length(host, 1)) &&
                (memcmp(v5_princ_component_contents(entry.principal, 1),
                v5_princ_component_contents(host, 1),
                v5_princ_component_length(host, 1)) == 0)) {
            if (princ != NULL) {
                krb5_free_principal(ctx, princ);
            }
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
            score = 4;
        }
        /* Favorite entry ("host" with the local hostname as the
         * instance, in the client's realm)? */
        if ((score < 5) &&
                (host != NULL) &&
                (v5_princ_component_count(entry.principal) == 2) &&
                krb5_realm_compare(ctx, entry.principal, creds->client) &&
                (v5_princ_component_length(entry.principal, 1) ==
                v5_princ_component_length(host, 1)) &&
                (memcmp(v5_princ_component_contents(entry.principal, 1),
                v5_princ_component_contents(host, 1),
                v5_princ_component_length(host, 1)) == 0) &&
                (v5_princ_component_length(entry.principal, 0) == 4) &&
                (memcmp(v5_princ_component_contents(entry.principal, 0),
                "host", 4) == 0)) {
            if (princ != NULL) {
                krb5_free_principal(ctx, princ);
            }
            i = krb5_copy_principal(ctx, entry.principal, &princ);
            if (i != 0) {
                warn("internal error copying principal name");
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
                krb5_kt_close(ctx, keytab);
                krb5_free_principal(ctx, host);
                return PAM_SERVICE_ERR;
            }
            score = 5;
        }
    }

    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    krb5_kt_close(ctx, keytab);
    krb5_free_principal(ctx, host);

    *service = princ;

    return PAM_SUCCESS;
}

static int
krbldap_validate_using_keytab(krb5_context ctx, krb5_creds *creds,
        const struct _pam_krb5_options *options, int *krberr) {
    int i;
    char *principal;
    krb5_principal princ;
    krb5_keytab keytab;
    krb5_verify_init_creds_opt opt;

    /* Try to figure out the name of a suitable service. */
    princ = NULL;
    krbldap_select_keytab_service(ctx, creds, options->keytab, &princ);

    /* Try to get a text representation of the principal to which the key
     * belongs, for logging purposes. */
    principal = NULL;
    if (princ != NULL) {
        i = krb5_unparse_name(ctx, princ, &principal);
    }

    /* Try to open the keytab. */
    keytab = NULL;
    if (options->keytab != NULL) {
        i = krb5_kt_resolve(ctx, options->keytab, &keytab);
        if (i != 0) {
            warn("error resolving keytab '%s'", options->keytab);
        }
    } else {
        i = krb5_kt_default(ctx, &keytab);
        if (i != 0) {
            warn("error resolving default keytab");
        }
    }

    /* Perform the verification checks using the service's key, assuming we
     * have some idea of what the service's name is, and that we can read
     * the key. */
    krb5_verify_init_creds_opt_init(&opt);
    i = krb5_verify_init_creds(ctx, creds, princ, keytab, NULL, &opt);
    *krberr = i;
    if (keytab != NULL) {
        krb5_kt_close(ctx, keytab);
    }
    if (princ != NULL) {
        krb5_free_principal(ctx, princ);
    }

    /* Log success or failure. */
    if (i == 0) {
        if (principal != NULL) {
            notice("TGT verified using key for '%s'", principal);
            v5_free_unparsed_name(ctx, principal);
        } else {
            notice("TGT verified");
        }
        return PAM_SUCCESS;
    } else {
        if (principal != NULL) {
            crit("TGT failed verification using keytab and "
                    "key for '%s': %s",
                    principal, v5_error_message(i));
            v5_free_unparsed_name(ctx, principal);
        } else {
            crit("TGT failed verification using keytab: %s",
                    v5_error_message(i));
        }
        return PAM_AUTH_ERR;
    }
}

static int
krbldap_validate(krb5_context ctx, krb5_creds *creds,
        struct _pam_krb5_user_info *userinfo,
        const struct _pam_krb5_options *options) {
    int ret, krberr;
    /* Obtain creds for a service for which we have keys in the keytab and
     * then just authenticate to it. */
    krberr = 0;
    ret = krbldap_validate_using_keytab(ctx, creds, options, &krberr);
    switch (ret) {
        case PAM_AUTH_ERR:
            switch (krberr) {
                case EACCES:
                case ENOENT:
                case KRB5_KT_NOTFOUND:
                    /* We weren't able to read the keytab. */
                    if (options->validate_user_user &&
                            (_pam_krb5_sly_looks_unsafe() == 0)) {
                        /* If it looks safe, see if we have an
                         * already-issued TGT that we can use to
                         * perform user-to-user authentication. It's
                         * not ideal, but it tells us that the KDC that
                         * issued this set of creds was the one that
                         * issued the older set, and validating those
                         * was some other process's problem. */
                        switch (krbldap_validate_using_ccache(ctx, creds,
                                userinfo,
                                options)) {
                            case PAM_SUCCESS:
                                ret = PAM_SUCCESS;
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return ret;
}

int
krbldap_get_creds(krb5_context ctx,
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
        int *expired,
        int *result) {
    int i;
    char realm_service[LINE_MAX];
    char *opt;
    const char *realm;
    struct pam_message message;
    struct _pam_krb5_prompter_data prompter_data;
    struct _pam_krb5_perms *saved_perms;
    krb5_principal service_principal;
    krb5_creds tmpcreds;
    krb5_ccache ccache;
    krb5_get_init_creds_opt *tmp_gicopts;

    /* In case we already have creds, get rid of them. */
    krb5_free_cred_contents(ctx, creds);
    memset(creds, 0, sizeof (*creds));

    /* Check some string lengths. */
    if (strchr(userinfo->unparsed_name, '@') != NULL) {
        realm = strchr(userinfo->unparsed_name, '@') + 1;
    } else {
        realm = options->realm;
    }
    if (strlen(service) + 1 +
            strlen(realm) + 1 +
            strlen(realm) + 1 >= sizeof (realm_service)) {
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
        memset(&service_principal, 0, sizeof (service_principal));
        if (krb5_parse_name(ctx, realm_service,
                &service_principal) == 0) {
            if (options->debug) {
                debug("attempting to read existing credentials "
                        "from %s", krb5_cc_default_name(ctx));
            }
            memset(&ccache, 0, sizeof (ccache));
            /* In case we're setuid/setgid, switch to the caller's
             * permissions. */
            saved_perms = _pam_krb5_switch_perms();
            if ((saved_perms != NULL) &&
                    (krb5_cc_default(ctx, &ccache) == 0)) {
                tmpcreds.client = userinfo->principal_name;
                tmpcreds.server = service_principal;
                i = krb5_cc_retrieve_cred(ctx, ccache, 0,
                        &tmpcreds, creds);
                /* FIXME: check if the creds are expired?
                 * What's the right error code if we check, and
                 * they are? */
                memset(&tmpcreds, 0, sizeof (tmpcreds));
                krb5_cc_close(ctx, ccache);
                /* In case we're setuid/setgid, restore the
                 * previous permissions. */
                if (saved_perms != NULL) {
                    if (_pam_krb5_restore_perms(saved_perms) != 0) {
                        krb5_free_cred_contents(ctx, creds);
                        memset(creds, 0, sizeof (*creds));
                        krb5_free_principal(ctx, service_principal);
                        return PAM_SYSTEM_ERR;
                    }
                    saved_perms = NULL;
                }
            } else {
                warn("error opening default ccache");
                i = KRB5_CC_NOTFOUND;
            }
            /* In case we're setuid/setgid, switch back to the
             * previous permissions if we didn't already. */
            if (saved_perms != NULL) {
                if (_pam_krb5_restore_perms(saved_perms) != 0) {
                    krb5_free_cred_contents(ctx, creds);
                    memset(creds, 0, sizeof (*creds));
                    krb5_free_principal(ctx, service_principal);
                    return PAM_SYSTEM_ERR;
                }
                saved_perms = NULL;
            }
            krb5_free_principal(ctx, service_principal);
        } else {
            warn("error parsing TGT principal name (%s) "
                    "(shouldn't happen)", realm_service);
            i = KRB5_REALM_CANT_RESOLVE;
        }
    } else {
        /* Contact the KDC. */
        prompter_data.ctx = ctx;
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
            warn("error resolving pkinit identity template \"%s\" "
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
                warn("error resolving preauth option \"%s\" "
                        "to a useful value",
                        options->preauth_options[i]);
            }
        }
#endif
        i = _krbldap_as_authenticate(ctx,
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
        debug("_krbldap_as_authenticate(%s) returned %d (%s)",
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
                switch (krbldap_validate(ctx, creds, userinfo, options)) {
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
            snprintf(realm_service, sizeof (realm_service),
                    PASSWORD_CHANGE_PRINCIPAL "@%s", realm);
            if (options->debug) {
                debug("key is expired. attempting to verify password "
                        "by obtaining credentials for %s", realm_service);
            }
            prompter_data.ctx = ctx;
            prompter_data.pamh = pamh;
            prompter_data.previous_password = password;
            prompter_data.options = options;
            prompter_data.userinfo = userinfo;
            memset(&tmpcreds, 0, sizeof (tmpcreds));
            if (options->debug && options->debug_sensitive) {
                debug("attempting with password=%s%s%s",
                        password ? "\"" : "",
                        password ? password : "(null)",
                        password ? "\"" : "");
            }
            i = v5_alloc_get_init_creds_opt(ctx, &tmp_gicopts);
            if (i == 0) {
                /* Set hard-coded defaults for password-changing creds
                 * which might not match generally-used options. */
                _pam_krb5_set_init_opts_for_pwchange(ctx,
                        tmp_gicopts,
                        options);
            } else {
                /* Try library defaults. */
                tmp_gicopts = NULL;
            }

            i = krb5_get_init_creds_password(ctx,
                    &tmpcreds,
                    userinfo->principal_name,
                    password,
                    prompter,
                    &prompter_data,
                    0,
                    realm_service,
                    tmp_gicopts);


            /*
            printf("User: [%s]\n", user);
            prompt_result = _pam_krb5_prompt_for(pamh, Y_("Password: "), &pass);
            printf("Pass: [%s]\n", pass);
            prompt_result = _krbldap_as_authenticate(user, pass);
            return PAM_SERVICE_ERR;
             */
            v5_free_get_init_creds_opt(ctx, tmp_gicopts);
            krb5_free_cred_contents(ctx, &tmpcreds);
            switch (i) {
                case 0:
                    /* Got password-changing creds, so warn about the
                     * expired password and continue. */
                    if (expired) {
                        *expired = 1;
                    }
                    if (options->warn == 1) {
                        message.msg = "Warning: password has expired.";
                        message.msg_style = PAM_TEXT_INFO;
                        _pam_krb5_conv_call(pamh, &message, 1, NULL);
                    }
                    if (options->debug) {
                        debug("attempt to obtain credentials for %s "
                                "succeeded", realm_service);
                    }
                    return PAM_SUCCESS;
                    break;
            }
            if (options->debug) {
                debug("attempt to obtain credentials for %s "
                        "failed: %s", realm_service, v5_error_message(i));
            }
            if (result) {
                *result = i;
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

/* END blatant copy from auth.c */

int _krbldap_as_authenticate(krb5_context context, krb5_creds *creds,
        krb5_principal client, char *password,
        krb5_prompter_fct prompter, void *data,
        krb5_deltat start_time, char *in_tkt_service,
        krb5_get_init_creds_opt *k5_gic_options) {
    LDAP *ldap;
    LDAPMessage *ldap_msg, *entry_msg;
    LDAPControl **controls;
    int rc;
    char *username;
    char *base = "dc=example,dc=com";
    char *user_dn;
    char ldap_filter[KRBLDAP_DYNAMIC_STRING_MAXSIZE];
    struct timeval timeout;
    int sizelimit = 1;
    timeout.tv_sec = 29;
    timeout.tv_usec = 0;


    /* LDAP allows for binding with null/empty password, which is an anonymous bind.
       For PAM, this must be equivalent to an authentication error. */
    if (password == NULL || password[0] == '\0') {
        return PAM_AUTH_ERR;
    }
    username = client->data->data;
    /* TODO: filter username characters not present in a whitelist? e.g. parens, which
            can be used for LDAP filter injection attacks. */
    printf("Username: [%s], Pass: [%s]\n", username, password);
    /* TODO: implement configuration for LDAP URL etc. */
    rc = ldap_initialize(&ldap, "ldap://localhost:1389");
    printf("rc: [%d], LDAP_SUCCESS: [%d]\n", rc, LDAP_SUCCESS);
    if (rc != LDAP_SUCCESS) {
        warn("error initializing LDAP, ldap_initialize return code: [%d]", rc);
        return PAM_SERVICE_ERR;
    }
    if (ldap == NULL) {
        warn("NULL LDAP session returned by ldap_initialize");
        return PAM_SERVICE_ERR;
    }
    int ldap_version = LDAP_VERSION3;
    ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    /* TODO: make the uid attribute configurable */
    snprintf(ldap_filter, sizeof ldap_filter, "(uid=%s)", username);
    printf("LDAP filter: [%s]\n", ldap_filter);
    rc = ldap_search_ext_s(ldap, base, LDAP_SCOPE_SUBTREE, ldap_filter, NULL,
            0, NULL, NULL, &timeout, sizelimit, &ldap_msg);
    printf("rc: [%d]\n", rc);
    entry_msg = ldap_first_entry(ldap, ldap_msg);
    if (entry_msg == NULL) {
        ldap_msgfree(ldap_msg);
        warn("No entries found for filter [%s]", ldap_filter);
        return PAM_SERVICE_ERR;
    }
    user_dn = ldap_get_dn(ldap, entry_msg);
    printf("user_dn: [%s]\n", user_dn);

    /**/
    char random_buf[4];
    krb5_data random_data;
    krb5_data *message_data;
    krb5_error_code code;
    krb5_init_creds_context icc = NULL;

    code = krb5_init_creds_init(context,
            client,
            NULL,
            NULL,
            0,
            k5_gic_options,
            &icc);
    if (code != 0) {
        warn("Kerberos error [%d] while initializing credentials: [%s]", code,
                error_message(code));
        goto cleanup;
    }
    icc->request = k5alloc(sizeof (krb5_kdc_req), &code);
    if (code != 0) {
        warn("Kerberos error [%d] while initializing request: [%s]", code,
                error_message(code));
        goto cleanup;
    }
    code = krb5_init_creds_set_password(context, icc, password);
    if (code != 0) {
        warn("Kerberos error [%d] while setting password: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    code = krb5_timeofday(context, &icc->request_time);
    if (code != 0) {
        warn("Kerberos error [%d] while setting request time: [%s]", code,
                error_message(code));
        goto cleanup;
    }
    // TODO: make icc->request not NULL

    // TODO: control the amount of retry attempts:
    if (icc->loopcount >= MAX_IN_TKT_LOOPS) {
        code = KRB5_GET_IN_TKT_LOOP;
        warn("Kerberos error [%d] after exceeding retry limit: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    /*
     * RFC 6113 requires a new nonce for the inner request on each try. It's
     * permitted to change the nonce even for non-FAST so we do here.
     */
    random_data.length = 4;
    random_data.data = (char *) random_buf;
    code = krb5_c_random_make_octets(context, &random_data);
    if (code != 0) {
        warn("Kerberos error [%d] making random data for nonce: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    /*
     * See RT ticket 3196 at MIT.  If we set the high bit, we may have
     * compatibility problems with Heimdal, because we (incorrectly) encode
     * this value as signed.
     */
    icc->request->nonce = 0x7fffffff & load_32_n(random_buf);
    krb5_free_data(context, icc->inner_request_body);
    icc->inner_request_body = NULL;
    /* TODO: encoding redundant? */
    code = encode_krb5_kdc_req_body(icc->request, &icc->inner_request_body);

    if (code != 0) {
        warn("Kerberos error [%d] encoding request body: [%s]", code,
                error_message(code));
        goto cleanup;
    }
    printf("request magic: [%d]\n", icc->request->magic);


    code = encode_krb5_as_req(icc->request, &icc->encoded_previous_request);
    if (code != 0) {
        warn("Kerberos error [%d] encoding request message: [%s]", code,
                error_message(code));
        goto cleanup;
    }


    struct berval berval;
    struct berval *retdata = NULL;
    char *retoid = NULL;

    /*
    BerElement *berelem;
    berelem = ber_alloc_t(LBER_USE_DER);
    if (berelem == NULL) {
        return PAM_BUF_ERR;
    }
    ber_printf(berelem, "{s}", username);
    rc = ber_flatten(berelem, &berval);
    if (rc < 0) {
        ber_free(berelem, 1);
        return PAM_BUF_ERR;
    }
    printf("flatten rc: [%d]\n", rc);
     */
    berval.bv_len = icc->encoded_previous_request->length;
    berval.bv_val = icc->encoded_previous_request->data;

    int debug = 0xffffff;
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
    rc = ldap_extended_operation_s(ldap, KRBLDAP_OID_EXOP_AS_REQ, &berval, NULL, NULL, &retoid, &retdata);
    ldap_memfree(retoid);
    ber_bvfree(retdata);
    printf("exop rc: [%d]\n", rc);
    /**/

    /*
            i = krb5_get_init_creds_password(ctx,
                                             creds,
                                             userinfo->principal_name,
                                             password,
                                             prompter,
                                             &prompter_data,
                                             0,
                                             realm_service,
                                             gic_options);
     */
cleanup:
    printf("\ndoing cleanup\n");
    ldap_msgfree(ldap_msg);
}
