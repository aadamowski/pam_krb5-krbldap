#ifndef pam_krb5_stash_h
#define pam_krb5_stash_h

#include "userinfo.h"

struct _pam_krb5_stash {
	char *key;
	krb5_context v5ctx;
	int v5result;
	char *v5file;
	krb5_creds v5creds;
#ifdef USE_KRB4
	int v4present;
	CREDENTIALS v4creds;
	char *v4file;
#endif
};

struct _pam_krb5_stash *_pam_krb5_stash_get(pam_handle_t *pamh,
					    struct _pam_krb5_user_info *info);

#endif
