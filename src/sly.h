#ifndef pam_krb5_sly_h
#define pam_krb5_sly_h

int _pam_krb5_sly_maybe_refresh(pam_handle_t *pamh, int flags,
				int argc, PAM_KRB5_MAYBE_CONST char **argv);

#endif
