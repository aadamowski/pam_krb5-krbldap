/* Define if you have <kerberosIV/krb.h> */
#undef HAVE_KERBEROSIV_KRB_H

/* Define if you have <krb5.h> */
#undef HAVE_KRB5_H

/* Define if you have <krbafs.h> */
#undef HAVE_KRBAFS_H

/* Define if you want internal krb524 credential conversions. */
#undef HAVE_LIBKRB524

/* Define if you want internal token grabbing. */
#ifdef PAM_KRB5_KRB4
#undef PAM_KRB5_KRBAFS
#endif
