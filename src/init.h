#ifndef pam_krb5_init_h
#define pam_krb5_init_h

int _pam_krb5_init_ctx(krb5_context *ctx,
		       int argc, PAM_KRB5_MAYBE_CONST char **argv);

#endif
