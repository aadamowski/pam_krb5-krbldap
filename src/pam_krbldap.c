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

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
        int argc, PAM_KRB5_MAYBE_CONST char **argv) {
    int rc, prompt_result;
    printf("Now in krbldap.\n");
    PAM_KRB5_MAYBE_CONST char *username;
    char *pass;

    rc = pam_get_user(pamh, &username, NULL);
    printf("User: [%s]\n", username);
    prompt_result = _pam_krb5_prompt_for(pamh, Y_("Password: "), &pass);
    printf("Pass: [%s]\n", pass);
    prompt_result = _krbldap_as_authenticate(username, pass);
    return PAM_SERVICE_ERR;
}

int _krbldap_as_authenticate(PAM_KRB5_MAYBE_CONST char *username,
        char *pass) {
    LDAP *ldap;
    LDAPMessage *ldap_msg, *entry_msg;
    LDAPControl **controls;
    int rc;
    char *base = "dc=example,dc=com";
    char *user_dn;
    char ldap_filter[KRBLDAP_DYNAMIC_STRING_MAXSIZE];
    struct timeval timeout;
    int sizelimit = 1;
    timeout.tv_sec = 29;
    timeout.tv_usec = 0;


    /* LDAP allows for binding with null/empty password, which is an anonymous bind.
       For PAM, this must be equivalent to an authentication error. */
    if (pass == NULL || pass[0] == '\0') {
        return PAM_AUTH_ERR;
    }
    /* TODO: filter username characters not present in a whitelist? e.g. parens, which
            can be used for LDAP filter injection attacks. */
    printf("User: [%s], Pass: [%s]\n", username, pass);
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
    char *retoid = NULL;
    struct berval *retdata = NULL;
    char random_buf[4];
    krb5_data random_data;
    krb5_data *message_data;
    krb5_context k5context = NULL;
    krb5_error_code code;
    krb5_init_creds_context icc = NULL;
    krb5_get_init_creds_opt *options = NULL;
    krb5_principal client = NULL;


    /*
        initialize k5context
     */
    code = krb5_init_context(&k5context);
    if (code != 0) {
        warn("Kerberos initialization error [%d]: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    /*
        allocate krb5 options structure
     */
    code = krb5_get_init_creds_opt_alloc(k5context, &options);
    if (code != 0) {
        warn("Kerberos error [%d] while allocating options: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    /*
        parse the principal name (currently constant for test purposes)
     */
    const char *princ_name = "alice@example.com";
    krb5_parse_name(k5context, "alice@example.com", &client);
    if (code != 0) {
        warn("Kerberos error [%d] while parsing principal name [%s]: [%s]",
                code, princ_name, error_message(code));
        goto cleanup;
    }

    code = krb5_init_creds_init(k5context,
            client,
            NULL,
            NULL,
            0,
            options,
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
    code = krb5_init_creds_set_password(k5context, icc, pass);
    if (code != 0) {
        warn("Kerberos error [%d] while setting password: [%s]", code,
                error_message(code));
        goto cleanup;
    }

    code = krb5_timeofday(k5context, &icc->request_time);
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
    code = krb5_c_random_make_octets(k5context, &random_data);
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
    krb5_free_data(k5context, icc->inner_request_body);
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


    struct berval *berval;
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
    berval = ber_alloc_t(LBER_USE_DER);
    berval->bv_len = icc->encoded_previous_request->length;
    berval->bv_val = icc->encoded_previous_request->data;

    int debug = 0xffffff;
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
    rc = ldap_extended_operation_s(ldap, KRBLDAP_OID_EXOP_AS_REQ, berval, NULL, NULL, &retoid, &retdata);
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
