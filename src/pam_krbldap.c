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
#include KRB5_H

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
	LDAPMessage *ldap_msg;
	LDAPControl **controls;
	struct berval berpass;
	int rc;

	/* LDAP allows for binding with null/empty password, which is an anonymous bind.
	   For PAM, this must be equivalent to an authentication error. */
	if (pass == NULL || pass[0] == '\0') {
		return PAM_AUTH_ERR;
	}
	printf("User: [%s], Pass: [%s]\n", username, pass);
	rc = ldap_initialize (&ldap, "ldap://stacja.amarczuk:389");
    printf("rc: [%d], LDAP_SUCCESS: [%d]\n", rc, LDAP_SUCCESS);
    if (rc != LDAP_SUCCESS) {
		warn("error initializing LDAP, ldap_initialize return code: [%d]", rc);
		return PAM_SERVICE_ERR;
    }
    if (ldap == NULL)
    {
		warn("NULL LDAP session returned by ldap_initialize");
        return PAM_SERVICE_ERR;
    }
/*
  rc = ldap_search_s (ldap, base, scope, filter, attrs, 0, &response);
  ldap_msg = ldap_first_entry (ldap, response);
  user_dn = ldap_get_dn (ldap, ldap_msg);
*/
}
