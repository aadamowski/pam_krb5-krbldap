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

#ifndef pam_krb5_v5_h
#define pam_krb5_v5_h

#include "options.h"
#include "stash.h"
#include "userinfo.h"

int v5_get_creds(krb5_context ctx,
		 pam_handle_t *pamh,
		 krb5_creds *creds,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 char *service,
		 char *password,
		 krb5_get_init_creds_opt *gic_options,
		 int *result);

int v5_get_creds_etype(krb5_context ctx,
		       struct _pam_krb5_user_info *userinfo,
		       struct _pam_krb5_options *options,
		       krb5_creds *current_creds, int wanted_etype,
		       krb5_creds **target_creds);

int v5_save(krb5_context ctx,
	    struct _pam_krb5_stash *stash,
	    struct _pam_krb5_user_info *userinfo,
	    struct _pam_krb5_options *options,
	    const char **ccname);

void v5_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	        struct _pam_krb5_options *options);

int v5_creds_check_initialized(krb5_context ctx, krb5_creds *creds);
int v5_creds_get_etype(krb5_context ctx, krb5_creds *creds);
void v5_creds_set_etype(krb5_context ctx, krb5_creds *creds, int etype);

void v5_free_unparsed_name(krb5_context ctx, char *name);
void v5_free_default_realm(krb5_context ctx, char *realm);
void v5_appdefault_string(krb5_context context,
			  const char *realm,
			  const char *option,
			  const char *default_value,
			  char **ret_value);
void v5_appdefault_boolean(krb5_context context,
			   const char *realm,
			   const char *option,
			   int default_value,
			   int *ret_value);

const char *v5_error_message(int error);

int v5_set_principal_realm(krb5_context ctx, krb5_principal *principal,
			   const char *realm);

#endif
