/*
 * Copyright 2003 Red Hat, Inc.
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

#ident "$Id$"

int
_pam_krb5_init_ctx(krb5_context *ctx,
		   int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	int try_secure = 1, i;
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "unsecure_for_debugging_only") == 0) {
			try_secure = 0;
		}
	}
#ifdef HAVE_INITIALIZE_KRB5_ERROR_TABLE
        initialize_krb5_error_table();
#endif
#ifdef HAVE_INITIALIZE_KRB4_ERROR_TABLE
        initialize_krb4_error_table();
#endif
#ifdef HAVE_INITIALIZE_KRB_ERROR_TABLE
        initialize_krb_error_table();
#endif
	*ctx = NULL;
#ifdef HAVE_KRB5_INIT_SECURE_CONTEXT
	if (try_secure) {
		i = krb5_init_secure_context(ctx);
		if (i != 0) {
			warn("error initializing kerberos: %d (%s)", i,
			     error_message(i));
		}
		return i;
	}
#endif
	i = krb5_init_context(ctx);
	if (i != 0) {
		warn("error initializing kerberos: %d (%s)", i,
		     error_message(i));
	}
	return i;
}
