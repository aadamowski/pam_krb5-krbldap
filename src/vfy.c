/*
 * Copyright 2010 Red Hat, Inc.
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

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#include "init.h"
#include "log.h"
#include "options.h"
#include "v5.h"

int
main(int argc, const char **argv)
{
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_creds mcreds, creds;
	krb5_keytab keytab;
	krb5_principal server;
	krb5_verify_init_creds_opt opts;
	int ret;

	ctx = NULL;
	ret = _pam_krb5_init_ctx(&ctx, argc, argv);
	if (ret != 0) {
		crit("error initializing Kerberos: %s", error_message(ret));
		return ret;
	}

	ccache = NULL;
	ret = krb5_cc_default(ctx, &ccache);
	if (ret != 0) {
		crit("error resolving ccache: %s", error_message(ret));
		return ret;
	}

	keytab = NULL;
	ret = krb5_kt_default(ctx, &keytab);
	if (ret != 0) {
		crit("error resolving keytab: %s", error_message(ret));
		return ret;
	}

	server = NULL;
	memset(&mcreds, 0, sizeof(mcreds));
	ret = krb5_cc_get_principal(ctx, ccache, &mcreds.client);
	if (ret != 0) {
		crit("error reading client name from ccache: %s",
		     error_message(ret));
		return ret;
	}
	ret = krb5_build_principal_ext(ctx, &mcreds.server,
				       v5_princ_realm_length(mcreds.client),
				       v5_princ_realm_contents(mcreds.client),
				       KRB5_TGS_NAME_SIZE,
				       KRB5_TGS_NAME,
				       v5_princ_realm_length(mcreds.client),
				       v5_princ_realm_contents(mcreds.client),
				       0);
	if (ret != 0) {
		crit("error building ticket granting server name: %s",
		     error_message(ret));
		return ret;
	}

	ret = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcreds, &creds);
	if (ret != 0) {
		crit("error reading ccache: %s", error_message(ret));
		return ret;
	}
	krb5_cc_close(ctx, ccache);

	krb5_verify_init_creds_opt_init(&opts);
	ret = krb5_verify_init_creds(ctx, &creds,
				     server, keytab, NULL,
				     &opts);
	if (ret != 0) {
		crit("error verifying creds: %s", error_message(ret));
	} else {
		printf("OK\n");
	}

	krb5_free_context(ctx);

	return ret;
}
