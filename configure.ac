AC_INIT(configure.ac)
AM_INIT_AUTOMAKE(pam_krb5,`rpm -q --specfile ${srcdir:-.}/pam_krb5.spec --qf '%{version}\n' | head -n1`)
AC_PROG_CC
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_PATH_PROG(KRB5_CONFIG,krb5-config,:,[$PATH:/usr/kerberos/bin:/usr/krb5/bin])
AC_ARG_WITH(krb4,
AC_HELP_STRING(--without-krb4,[Disable Kerberos IV support.]),
	    krb4=$withval,
	    krb4=yes)
if test x$krb4 != xno ; then
	AC_PATH_PROG(KRB4_CONFIG,krb4-config,:,[$PATH:/usr/kerberos/bin:/usr/krb4/bin])
	if $KRB5_CONFIG --libs krb4 > /dev/null 2> /dev/null; then
		AC_MSG_RESULT(Using krb4 provided with krb5.)
		KRB4_CONFIG="$KRB5_CONFIG krb4"
	fi
else
	KRB4_CONFIG=:
fi

KRB5_BINDIR=`dirname $KRB5_CONFIG`
AC_SUBST(KRB5_BINDIR)

AC_CHECK_LIB(resolv,main)
KRB5_CFLAGS=`$KRB5_CONFIG --cflags krb5`
KRB5_LIBS=`$KRB5_CONFIG --libs krb5`
KRB5_LDFLAGS="`$KRB5_CONFIG --libs | sed s,'-l[[^ 	]]*',,g`"
LIBS="$LIBS `$KRB5_CONFIG --libs | sed s,'-l[[^ 	]]*',,g`"
LDFLAGS="$LDFLAGS $KRB5_LDFLAGS"
if test x$krb4 != xno ; then
	KRB4_CFLAGS=`$KRB4_CONFIG --cflags krb4`
	KRB4_LIBS=`$KRB4_CONFIG --libs krb4`
	KRB4_LDFLAGS="`$KRB4_CONFIG --libs | sed s,'-l[[^ 	]]*',,g`"
	LIBS="$LIBS `$KRB4_CONFIG --libs | sed s,'-l[[^ 	]]*',,g`"
	LDFLAGS="$LDFLAGS $KRB4_LDFLAGS"
fi

AC_MSG_CHECKING(for KRB5_CFLAGS)
AC_SUBST(KRB5_CFLAGS)
AC_MSG_RESULT($KRB5_CFLAGS)

AC_MSG_CHECKING(for KRB5_LIBS)
AC_SUBST(KRB5_LIBS)
AC_MSG_RESULT($KRB5_LIBS)

if test x$krb4 != xno ; then
	AC_MSG_CHECKING(for KRB4_LIBS)
	AC_SUBST(KRB4_LIBS)
	AC_MSG_RESULT($KRB4_LIBS)
	AC_MSG_CHECKING(for KRB4_CFLAGS)
	AC_SUBST(KRB4_CFLAGS)
	AC_MSG_RESULT($KRB4_CFLAGS)
fi


AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_HEADERS(security/pam_modules.h)
AC_CHECK_HEADERS(security/pam_misc.h)
AC_CHECK_FUNCS(getpwnam_r __posix_getpwnam_r)
AC_CHECK_FUNC(crypt,,[AC_CHECK_LIB(crypt,crypt)])

# We need GNU sed for this to work, but okay.
KRB5_CPPFLAGS=`echo $KRB5_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`
KRB4_CPPFLAGS=`echo $KRB4_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`

CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS $KRB4_CPPFLAGS"
CFLAGS="$CFLAGS $KRB5_CFLAGS $KRB4_CFLAGS"

AC_CHECK_HEADERS(krb5.h)
if test x$ac_cv_header_krb5_h != xyes ; then
	AC_MSG_ERROR(you must have Kerberos 5 development files to build $PACKAGE)
fi
if test x$krb4 != xno ; then
	AC_CHECK_HEADER(krb.h,,[AC_CHECK_HEADER(kerberosIV/krb.h)])
	if test x$ac_cv_header_krb_h = xyes ; then
		AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
		AC_DEFINE(KRB4_DES_H,[<des.h>],[Define to the name of your Kerberos IV des.h header.])
		AC_DEFINE(KRB4_KRB_H,[<krb.h>],[Define to the name of your Kerberos IV krb.h header.])
		AC_CHECK_HEADER(krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
	else
		if test x$ac_cv_header_kerberosIV_krb_h = xyes ; then
			AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
			AC_DEFINE(KRB4_DES_H,[<kerberosIV/des.h>],[Define to the name of your Kerberos IV des.h header.])
			AC_DEFINE(KRB4_KRB_H,[<kerberosIV/krb.h>],[Define to the name of your Kerberos IV krb.h header.])
			AC_CHECK_HEADER(kerberosIV/krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<kerberosIV/krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
		else
			AC_MSG_WARN([no Kerberos IV functionality available])
		fi
	fi
fi

LIBSsave="$LIBS"
LIBS="$LIBS $KRB5_LIBS $KRB4_LIBS"
AC_CHECK_FUNCS(krb_life_to_time krb_time_to_life krb5_init_secure_context krb5_free_unparsed_name krb5_free_default_realm krb5_set_principal_realm krb_in_tkt in_tkt krb_save_credentials save_credentials)
LIBS="$LIBSsave"
headers='
#include <stdio.h>
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#if STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <krb5.h>'
AC_CHECK_DECL(error_message,
	      [AC_DEFINE(HAVE_ERROR_MESSAGE_DECL,1,[Define if your krb5.h declares the error_message() function.])],,[$headers])
AC_CHECK_HEADERS(com_err.h et/com_err.h)

AC_CHECK_DECL(krb5_os_localaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_LOCALADDR,1,[Define if your krb5.h declares the krb5_os_localaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_os_hostaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_HOSTADDR,1,[Define if your krb5.h declares the krb5_os_hostaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_copy_addr,
	      [AC_DEFINE(HAVE_KRB5_COPY_ADDR,1,[Define if your krb5.h declares the krb5_copy_addr() function.])],,[$headers])
AC_CHECK_DECL(krb5_get_all_client_addrs,
	      [AC_DEFINE(HAVE_KRB5_GET_ALL_CLIENT_ADDRS,1,[Define if your krb5.h declares the krb5_get_all_client_addrs() function.])],,[$headers])

AC_CHECK_TYPES(krb5_const_realm,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.keyblock,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.session,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.enctype,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.keytype,,,[$headers])

LIBSsave="$LIBS"
LIBS="$LIBS $KRB5_LIBS $KRB4_LIBS"
AC_CHECK_FUNC(krb524_convert_creds_kdc,,[AC_CHECK_LIB(krb524,krb524_convert_creds_kdc,,[AC_CHECK_LIB(54,krb524_convert_creds_kdc)])])
AC_CHECK_FUNCS(krb5_524_convert_creds krb524_convert_creds_kdc)
if test x$ac_cv_function_krb5_524_convert_creds = xyes ; then
	AC_DEFINE(HAVE_KRB5_524_CONVERT_CREDS,1,[Define if you have the krb5_524_convert_creds function.])
else
	if test x$ac_cv_lib_krb524_krb5_524_convert_creds_kdc = xyes ; then
		AC_DEFINE(HAVE_KRB524_CONVERT_CREDS_KDC,1,[Define if you have the krb524_convert_creds_kdc function.])
		KRB5_LIBS="$KRB5_LIBS -lkrb524"
	else
		if test x$ac_cv_lib_54_krb5_524_convert_creds_kdc = xyes ; then
			AC_DEFINE(HAVE_KRB524_CONVERT_CREDS_KDC,1,[Define if you have the krb524_convert_creds_kdc function.])
			KRB5_LIBS="$KRB5_LIBS -l54"
		fi
	fi
fi
LIBS="$LIBSsave"

LIBSsave="$LIBS"
AC_CHECK_FUNC(dlopen,,[AC_CHECK_LIB(dl,dlopen)])
AC_CHECK_FUNC(pam_get_item,,[AC_CHECK_LIB(pam,pam_get_item)])
have_misc_conv=no
AC_CHECK_FUNC(misc_conv,have_misc_conv=yes,
	      [AC_CHECK_LIB(pam_misc,misc_conv,have_misc_conv=yes)])
if test x$have_misc_conv = xyes ; then
	AC_DEFINE(HAVE_MISC_CONV,1,[Define if you have the misc_conv function.])
fi
PAM_LIBS="$LIBS"
LIBS="$LIBSsave"
AC_SUBST(PAM_LIBS)

AC_ARG_ENABLE(default-realm,AC_HELP_STRING([--enable-default-realm=REALM],[last-ditch fallback realm (default is EXAMPLE.COM)]),default_realm=$enableval,default_realm=EXAMPLE.COM)
AC_DEFINE_UNQUOTED(DEFAULT_REALM,"$default_realm",[Define to the realm name which will be used if no realm is given as a parameter and none is given in krb5.conf.])
AC_MSG_RESULT([Using "$default_realm" as the default realm])
AC_ARG_ENABLE(default-ccache-dir,AC_HELP_STRING([--enable-default-ccache-dir=DIRECTORY],[default directory in which ccache files will be stored (default is /tmp)]),default_ccache_dir=$enableval,default_ccache_dir=/tmp)
AC_DEFINE_UNQUOTED(DEFAULT_CCACHE_DIR,"$default_ccache_dir",[Define to the name of the directory in which ccache files will be stored by default.])
AC_MSG_RESULT([Using "$default_ccache_dir" to store ccache files])
AC_ARG_ENABLE(default-keytab-location,AC_HELP_STRING([--enable-default-keytab-location=/etc/krb5.keytab],[default location for local keys used for verifying TGTs (default is /etc/krb5.keytab)]),default_keytab=$enableval,default_keytab=/etc/krb5.keytab)
AC_DEFINE_UNQUOTED(DEFAULT_KEYTAB_LOCATION,"$default_keytab",[Define to the default location for your keytab file, which will be used for verifying TGTs.])
DEFAULT_KEYTAB="$default_keytab"
AC_SUBST(DEFAULT_KEYTAB)
AC_MSG_RESULT([Using "$default_realm" as the default keytab])

PAM_KRB5_APPNAME=pam
AC_DEFINE_UNQUOTED(PAM_KRB5_APPNAME,"$PAM_KRB5_APPNAME",[Define to the application name, which defines which appdefaults section will be expected to hold this module's configuration in krb5.conf.])
AC_SUBST(PAM_KRB5_APPNAME)

AC_DEFINE(PAM_KRB5_MAYBE_CONST,[const],[Define to the proper qualifier (either const or nothing) for your PAM implementation.])
AC_DEFINE(PASSWORD_CHANGE_PRINCIPAL,["kadmin/changepw"],[Define to the principal name of the password-changing service for any given realm.])

if test x$GCC = xyes ; then
	AC_ARG_ENABLE(extra-warnings,AC_HELP_STRING([--enable-extra-warnings],[enable additional GCC-specific warnings (default is no)]),[CFLAGS="$CFLAGS -Wall -Wextra -Wimplicit -Wunused -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wcast-align -Wno-unused-parameters"])
	AC_ARG_ENABLE(Werror,AC_HELP_STRING([--enable-Werror],[enable -Werror as a compile flag (default is no)]),[CFLAGS="$CFLAGS -Werror"])
fi

AH_VERBATIM([PAM_KRB5_GNUC_PRINTF_DEFINED],
[/* Add attribute tags to help spot format specifier problems. */
 #ifdef __GNUC__
 #define PAM_KRB5_GNUC_PRINTF(__x,__y) __attribute__((format(printf,__x,__y)))
 #else
 #define PAM_KRB5_GNUC_PRINTF(__x,__y)
 #endif
])


pam_krb5_pkgsecuritydir=`eval echo $libdir/security/$PACKAGE | sed s,^NONE,$ac_default_prefix,`
AC_DEFINE_UNQUOTED(PKGSECURITYDIR,"$pam_krb5_pkgsecuritydir",[The location of pam_krb5 helpers.])

TESTDIR=`cd ${ac_top_builddir:-.}; /bin/pwd`/tests
TESTHOST=`hostname`
AC_SUBST(TESTDIR)
AC_SUBST(TESTHOST)
AC_SUBST(default_ccache_dir)

AC_CONFIG_HEADER(config.h)
AC_OUTPUT([
Makefile
src/Makefile
src/pam_krb5.5
src/pam_krb5.8
tests/Makefile
tests/config/Makefile
tests/config/krb5.conf
tests/config/kdc.conf
tests/config/krb.conf
tests/kdc/Makefile
tests/tools/Makefile
tests/tools/klist_t
tests/tools/klist_f
tests/tools/klist_c
tests/tools/klist_a
tests/tools/klist_4
])
