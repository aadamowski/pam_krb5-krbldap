#ifndef pam_krb5_v4_h
#define pam_krb5_v4_h

#include "options.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"

int v4_get_creds(krb5_context ctx,
		 pam_handle_t *pamh,
		 struct _pam_krb5_stash *stash,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 char *password,
		 int *result);

int v4_save(krb5_context ctx,
	    struct _pam_krb5_stash *stash,
	    struct _pam_krb5_user_info *userinfo,
	    struct _pam_krb5_options *options,
	    const char **ccname);
void v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	        struct _pam_krb5_options *options);

#endif
