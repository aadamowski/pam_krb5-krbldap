#ifndef pam_krb5_tokens_h
#define pam_krb5_tokens_h

int tokens_obtain(struct _pam_krb5_options *options);
int tokens_release(struct _pam_krb5_options *options);

#endif
