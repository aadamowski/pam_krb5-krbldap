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
