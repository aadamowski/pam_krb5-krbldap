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
