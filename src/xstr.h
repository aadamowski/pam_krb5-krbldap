#ifndef pam_krb5_xstr_h
#define pam_krb5_xstr_h

int xstrlen(const char *s);
char *xstrdup(const char *s);
char *xstrndup(const char *s, int n);

#endif
