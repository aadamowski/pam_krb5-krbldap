/* Define if you have kerberosIV/krb.h */
#undef HAVE_KERBEROSIV_KRB_H

/* Define if you have krb5.h */
#undef HAVE_KRB5_H

/* Define if you have krbafs.h */
#undef HAVE_KRBAFS_H

/* Define if you want internal token grabbing. */
#ifdef PAM_KRB5_KRB4
#undef PAM_KRB5_KRBAFS
#endif

/* Define if your Kerberos IV support includes krb.h instead of kerberosIV/krb.h */
#undef HAVE_KRB_H

/* Define if you want TGT validation. */
#undef HAVE_VALIDATION

/* Define if your in_tkt dies if the ticket file exists. */
#undef IN_TKT_USES_EXCL

/* Define if your Kerberos 5 distribution is Heimdal. */
#undef HEIMDAL

/* Define if your Kerberos IV distribution is KTH Kerberos. */
#undef KTH_KRB4
