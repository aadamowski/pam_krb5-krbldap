AC_INIT(configure.ac)
AC_PREREQ(2.59)
AM_INIT_AUTOMAKE(pam_krb5,2.3.13)
AC_PROG_CC
AC_LANG([C])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AM_MAINTAINER_MODE

dnl AC_MSG_CHECKING(for -as-needed or equivalent)
dnl savedCFLAGS="$CFLAGS"
dnl for flag in --as-needed -as-needed -Wl,--as-needed -Wl,-as-needed ; do
dnl     if test x"$LD_AS_NEEDED" = x ; then
dnl     	CFLAGS="$savedCFLAGS $flag"
dnl     	AC_LINK_IFELSE(AC_LANG_PROGRAM(,return 0;),[LD_AS_NEEDED=$flag])
dnl     fi
dnl done
dnl AC_MSG_RESULT(${LD_AS_NEEDED:-not found})
dnl CFLAGS="$savedCFLAGS"
AC_SUBST(LD_AS_NEEDED)

AC_PATH_PROG(KRB5_CONFIG,krb5-config,:,[$PATH:/usr/kerberos/bin:/usr/krb5/bin])
if test $KRB5_CONFIG = : ; then
	AC_MSG_ERROR(krb5-config not found)
fi
KRB5_BINDIR=`dirname $KRB5_CONFIG`
AC_SUBST(KRB5_BINDIR)

AC_ARG_WITH(os-distribution,
[AC_HELP_STRING([--with-os-distribution="Super Duper Linux"],[Override the default OS distribution name in man pages. (default is "Red Hat Linux")])],
	    OS_DISTRIBUTION="$withval",
	    OS_DISTRIBUTION="Red Hat Linux")
AC_SUBST(OS_DISTRIBUTION)

KRB4_BINDIR=
AC_ARG_WITH(krb4,
AC_HELP_STRING(--with-krb4[=AUTO],[Provide Kerberos IV support if possible.]),
	    krb4=$withval,
	    krb4=AUTO)
if test x$krb4 != xno ; then
	AC_PATH_PROG(KRB4_CONFIG,krb4-config,:,[$PATH:/usr/kerberos/bin:/usr/krb4/bin])
	if test $KRB4_CONFIG = : ; then
		if $KRB5_CONFIG --libs krb4 | grep -e -lkrb4 > /dev/null 2> /dev/null; then
			AC_MSG_RESULT(Using krb4 provided with krb5.)
			KRB4_CONFIG="$KRB5_CONFIG krb4"
			krb4=yes
		else
			if test x$krb4 = xyes ; then
				AC_MSG_ERROR(krb4 not found)
			else
				AC_MSG_WARN(krb4 not found, disabling)
				krb4=no
			fi
		fi
	else
		AC_MSG_RESULT(Using krb4 provided by $KRB4_CONFIG.)
		krb4=yes
		KRB4_BINDIR=`dirname $KRB4_CONFIG`
	fi
fi
AC_SUBST(KRB4_BINDIR)
if test x$krb4 != xno ; then
	MAN_KRB4=""
	NO_MAN_KRB4=".\\\" "
else
	KRB4_CONFIG=:
	MAN_KRB4=".\\\" "
	NO_MAN_KRB4=""
fi
AM_CONDITIONAL(V4,[test "x$krb4" = xyes])

AC_PATH_PROG(KRB5KDC,krb5kdc,:,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
if test x$KRB5KDC = x: ; then
	unset ac_cv_path_KRB5KDC
	AC_PATH_PROG(KRB5KDC,kdc,:,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
fi
AC_PATH_PROG(KRB524D,krb524d,:,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
AC_PATH_PROG(KADMIND,kadmind,:,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
AC_PATH_PROG(KADMIN,kadmin,:,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
if test x$KADMIN != x: ; then
	KADMINMAYBELOCAL="$KADMIN --local"
else
	KADMINMAYBELOCAL=":"
fi
AC_PATH_PROG(KADMINLOCAL,kadmin.local,$KADMINMAYBELOCAL,[${KRB5_BINDIR}:${KRB5_BINDIR}/../sbin:${KRB5_BINDIR}/../libexec])
AM_CONDITIONAL(KRB5KDC,[test x$KRB5KDC != x: ])
AM_CONDITIONAL(KRB524D,[test x$KRB524D != x: ])
AM_CONDITIONAL(KADMIND,[test x$KADMIND != x: ])
AM_CONDITIONAL(KADMINLOCAL,[test x$KADMINLOCAL != x: ])
AC_SUBST(KRB5KDC)
AC_SUBST(KRB524D)
AC_SUBST(KADMIND)
AC_SUBST(KADMINLOCAL)

AC_ARG_WITH(afs,
[AC_HELP_STRING(--without-afs,[Disable AFS support (default is AUTO).])],
	    afs=$withval,
	    afs=AUTO)
if test x$afs != xno ; then
	AC_MSG_CHECKING(if pam_krb5 knows how to set AFS tokens on $host_os)
	case x$host_os in
	*linux|*linux-*|*-sun-*)	afs=yes;;
	*)				afs=no;;
	esac
	AC_MSG_RESULT($afs)
fi

if test x$afs = xyes ; then
	AC_DEFINE(HAVE_AFS,1,[Define to enable token-setting support.])
	MAN_AFS=""
	NO_MAN_AFS=".\\\" "
else
	MAN_AFS=".\\\" "
	NO_MAN_AFS=""
fi
AM_CONDITIONAL(AFS,[test "x$afs" = xyes])

AC_ARG_WITH(default-chpw-prompt,
[AC_HELP_STRING(--with-default-chpw-prompt="gnome-screensaver",[Set the default value of the "chpw_prompt" option (no default).])],
	    DEFAULT_CHPW_PROMPT="$withval",
	    DEFAULT_CHPW_PROMPT=)
AC_DEFINE_UNQUOTED(DEFAULT_CHPW_PROMPT,"$DEFAULT_CHPW_PROMPT",[Set to the default value for the "chpw_prompt" setting.])
AC_SUBST(DEFAULT_CHPW_PROMPT)

AC_ARG_WITH(default-external,
[AC_HELP_STRING(--with-default-external="sshd sshd-rekey gssftp",[Set the default value of the "external" option (default is "sshd").])],
	    DEFAULT_EXTERNAL="$withval",
	    DEFAULT_EXTERNAL=sshd)
AC_DEFINE_UNQUOTED(DEFAULT_EXTERNAL,"$DEFAULT_EXTERNAL",[Set to the default value for the "external" setting.])
AC_SUBST(DEFAULT_EXTERNAL)

AC_ARG_WITH(default-multiple-ccaches,
[AC_HELP_STRING(--with-default-multiple-ccaches="su su-l",[Set the default value of the "multiple_ccaches" option (default is "su su-l").])],
	    DEFAULT_MULTIPLE_CCACHES="$withval",
	    DEFAULT_MULTIPLE_CCACHES="su su-l")
AC_DEFINE_UNQUOTED(DEFAULT_MULTIPLE_CCACHES,"$DEFAULT_MULTIPLE_CCACHES",[Set to the default value for the "multiple_ccaches" setting.])
AC_SUBST(DEFAULT_MULTIPLE_CCACHES)

AC_ARG_WITH(default-no-cred-session,
[AC_HELP_STRING(--with-default-no-cred-session="sshd",[Set the default value of the "no_cred_session" option (default is "sshd").])],
	    DEFAULT_NO_CRED_SESSION="$withval",
	    DEFAULT_NO_CRED_SESSION=sshd)
AC_DEFINE_UNQUOTED(DEFAULT_NO_CRED_SESSION,"$DEFAULT_NO_CRED_SESSION",[Set to the default value for the "no_cred_session" setting.])
AC_SUBST(DEFAULT_NO_CRED_SESSION)

AC_ARG_WITH(default-use-shmem,
[AC_HELP_STRING(--with-default-use-shmem="sshd",[Set the default value of the "use_shmem" option (default is "sshd").])],
	    DEFAULT_USE_SHMEM="$withval",
	    DEFAULT_USE_SHMEM=sshd)
AC_DEFINE_UNQUOTED(DEFAULT_USE_SHMEM,"$DEFAULT_USE_SHMEM",[Set to the default value for the "use-shmem" setting.])
AC_SUBST(DEFAULT_USE_SHMEM)

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
	AC_MSG_CHECKING(for KRB4_CFLAGS)
	AC_SUBST(KRB4_CFLAGS)
	AC_MSG_RESULT($KRB4_CFLAGS)
	AC_MSG_CHECKING(for KRB4_LIBS)
	AC_SUBST(KRB4_LIBS)
	AC_MSG_RESULT($KRB4_LIBS)
fi

AC_SUBST(MAN_AFS)
AC_SUBST(NO_MAN_AFS)
AC_SUBST(MAN_KRB4)
AC_SUBST(NO_MAN_KRB4)

AC_CHECK_HEADERS(sys/ioccom.h inttypes.h stdint.h)
AC_CHECK_HEADERS(security/pam_appl.h)
if test x$ac_cv_header_security_pam_appl_h != xyes ; then
	AC_MSG_ERROR([you must have PAM development files to build $PACKAGE])
fi
AC_CHECK_HEADERS(security/pam_modules.h)
if test x$ac_cv_header_security_pam_modules_h != xyes ; then
	AC_MSG_ERROR([you must have PAM development files to build $PACKAGE])
fi
AC_CHECK_HEADERS(security/pam_misc.h)
AC_CHECK_TYPES([long long])
AC_CHECK_FUNCS(getpwnam_r __posix_getpwnam_r strtoll)
AC_CHECK_FUNC(crypt,,[AC_CHECK_LIB(crypt,crypt)])

# We need GNU sed for this to work, but okay.
KRB5_CPPFLAGS=`echo $KRB5_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`
KRB4_CPPFLAGS=`echo $KRB4_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`

CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS $KRB4_CPPFLAGS"
CFLAGS="-g"
CFLAGS="$CFLAGS $KRB5_CFLAGS $KRB4_CFLAGS"

AC_CHECK_HEADERS(krb5.h krb5/krb5.h)
if test x$ac_cv_header_krb5_h != xyes ; then
	if test x$ac_cv_header_krb5_krb5_h != xyes ; then
		AC_MSG_ERROR(you must have Kerberos 5 development files to build $PACKAGE)
	fi
fi
if test x$ac_cv_header_krb5_h = xyes ; then
	AC_DEFINE(KRB5_H,[<krb5.h>],[Define to the name of your Kerberos 5 header.])
else
	AC_DEFINE(KRB5_H,[<krb5/krb5.h>],[Define to the name of your Kerberos 5 header.])
fi

USE_KRB4=0
if test x$krb4 != xno ; then
	AC_CHECK_HEADER(krb.h,,[AC_CHECK_HEADER(kerberosIV/krb.h)])
	if test x$ac_cv_header_krb_h = xyes ; then
		AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
		USE_KRB4=1
		AC_DEFINE(KRB4_DES_H,[<des.h>],[Define to the name of your Kerberos IV des.h header.])
		AC_DEFINE(KRB4_KRB_H,[<krb.h>],[Define to the name of your Kerberos IV krb.h header.])
		AC_CHECK_HEADER(krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
	else
		if test x$ac_cv_header_kerberosIV_krb_h = xyes ; then
			AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
			USE_KRB4=1
			AC_DEFINE(KRB4_DES_H,[<kerberosIV/des.h>],[Define to the name of your Kerberos IV des.h header.])
			AC_DEFINE(KRB4_KRB_H,[<kerberosIV/krb.h>],[Define to the name of your Kerberos IV krb.h header.])
			AC_CHECK_HEADER(kerberosIV/krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<kerberosIV/krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
		else
			AC_MSG_WARN([no Kerberos IV functionality available])
		fi
	fi
fi
AC_SUBST(USE_KRB4)
AM_CONDITIONAL(USE_KRB4,[test $USE_KRB4 -eq 1])

LIBSsave="$LIBS"
LIBS="$LIBS $KRB5_LIBS $KRB4_LIBS"
AC_CHECK_FUNCS(krb_life_to_time krb_time_to_life krb5_init_secure_context krb5_free_unparsed_name krb5_free_default_realm krb5_set_principal_realm krb5_get_prompt_types krb_in_tkt in_tkt krb_save_credentials save_credentials krb5_get_init_creds_opt_alloc krb5_get_init_creds_opt_free krb5_get_init_creds_opt_set_pkinit krb5_get_init_creds_opt_set_pa krb5_get_init_creds_opt_set_change_password_prompt krb5_get_init_creds_opt_set_canonicalize krb5_parse_name_flags krb5_change_password krb5_set_password krb5_xfree krb5_allow_weak_crypto krb5_enctype_enable krb5_enctype_to_string krb5_auth_con_setuserkey krb5_auth_con_setuseruserkey krb5_aname_to_localname krb5_set_trace_callback)
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
#include <krb5.h>
'
if test x$ac_cv_func_krb5_get_init_creds_opt_free = xyes ; then
	AC_MSG_CHECKING([if krb5_get_init_creds_opt_free() takes a context])
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <krb5.h>],[
					  krb5_get_init_creds_opt_free(NULL,
					 			       NULL);]),
	[AC_DEFINE(KRB5_GET_INIT_CREDS_OPT_ALLOC_FREE_TAKES_2_ARGS,1,
		   [Define if krb5_get_init_creds_opt_free() takes two arguments.])
	 AC_MSG_RESULT([yes])],
	AC_MSG_RESULT([no]))
fi
if test x$ac_cv_func_krb5_get_init_creds_opt_set_canonicalize = xyes ; then
	AC_MSG_CHECKING([if krb5_get_init_creds_opt_set_canonicalize() takes a context])
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <krb5.h>],[
					  krb5_get_init_creds_opt_set_canonicalize(NULL, NULL, 0);]),
	[AC_DEFINE(KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE_TAKES_3_ARGS,1,
		   [Define if krb5_get_init_creds_opt_set_canonicalize() takes three arguments.])
	 AC_MSG_RESULT([yes])],
	AC_MSG_RESULT([no]))
fi
if test x$ac_cv_func_krb5_get_init_creds_opt_set_pkinit = xyes ; then
	AC_MSG_CHECKING([if krb5_get_init_creds_opt_set_pkinit() takes a pool and a CRL])
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <krb5.h>],[
					  krb5_get_init_creds_opt_set_pkinit(NULL,
					  				     NULL,
					  				     NULL,
					  				     NULL,
					  				     NULL,
					  				     NULL,
					  				     NULL,
									     0,
									     NULL,
									     NULL,
									     NULL);]),
	[AC_DEFINE(KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_TAKES_11_ARGS,1,
		   [Define if krb5_get_init_creds_opt_set_pkinit() takes 11 arguments.])
	 AC_MSG_RESULT([yes])],
	AC_MSG_RESULT([no]))
fi
if test x$ac_cv_func_krb5_enctype_to_string = xyes ; then
	AC_MSG_CHECKING([if krb5_enctype_to_string() takes a size third])
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <krb5.h>],[
					  char __buf;
					  krb5_enctype_to_string(0, &__buf, sizeof(__buf));]),
	[AC_DEFINE(KRB5_ENCTYPE_TO_STRING_TAKES_A_SIZE_THIRD,1,
		   [Define if krb5_enctype_to_string() takes a size third.])
	 AC_MSG_RESULT([yes])],
	AC_MSG_RESULT([no]))
fi

if test x$ac_cv_func_krb5_set_trace_callback = xyes ; then
	MAN_TRACE=""
	NO_MAN_TRACE=".\\\" "
else
	MAN_TRACE=".\\\" "
	NO_MAN_TRACE=""
fi
AC_SUBST(NO_MAN_TRACE)
AC_SUBST(MAN_TRACE)

AC_CHECK_DECL(error_message,
	      [AC_DEFINE(HAVE_ERROR_MESSAGE_DECL,1,[Define if your krb5.h declares the error_message() function.])],,[$headers])
AC_CHECK_HEADERS(com_err.h et/com_err.h)

USE_ADDRESSES=0
AC_CHECK_DECL(krb5_copy_addr,
	      [AC_DEFINE(HAVE_KRB5_COPY_ADDR,1,[Define if your krb5.h declares the krb5_copy_addr() function.])],,[$headers])
AC_CHECK_DECL(krb5_os_hostaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_HOSTADDR,1,[Define if your krb5.h declares the krb5_os_hostaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_os_localaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_LOCALADDR,1,[Define if your krb5.h declares the krb5_os_localaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_get_all_client_addrs,
	      [AC_DEFINE(HAVE_KRB5_GET_ALL_CLIENT_ADDRS,1,[Define if your krb5.h declares the krb5_get_all_client_addrs() function.])],,[$headers])
if test x$ac_cv_decl_krb5_copy_addr = xyes ; then
	if test x$ac_cv_decl_krb5_os_hostaddr = xyes ; then
		if test x$ac_cv_decl_krb5_os_localaddr = xyes ; then
			USE_ADDRESSES=1
		fi
	fi
fi
if test x$ac_cv_decl_krb5_get_all_client_addrs = xyes ; then
	USE_ADDRESSES=1
fi
AC_SUBST(USE_ADDRESSES)
AM_CONDITIONAL(USE_ADDRESSES,[test $USE_ADDRESSES -eq 1])

if test x$ac_cv_func_krb5_get_init_creds_opt_alloc = xyes ; then
	if test x$ac_cv_func_krb5_get_init_creds_opt_free = xyes ; then
		AC_DEFINE(HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC_FREE,1,[Define if your library provides both `krb5_get_init_creds_opt_alloc' and `krb5_get_init_creds_opt_free'.])
	fi
fi

AC_CHECK_TYPES(krb5_const_realm,,,[$headers])
AC_CHECK_TYPES(krb5_addresses,,,[$headers])
AC_CHECK_TYPES(krb5_principal_data,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.keyblock,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.session,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.is_skey,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.flags.i,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.flags.b,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.ticket_flags,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.enctype,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.length,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.contents,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.keytype,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.keyvalue,,,[$headers])
AC_CHECK_MEMBERS(krb5_address.addr_type,,,[$headers])
AC_CHECK_MEMBERS(krb5_address.address,,,[$headers])
AC_CHECK_MEMBERS(krb5_address.addrtype,,,[$headers])
AC_CHECK_MEMBERS(krb5_address.length,,,[$headers])
AC_CHECK_MEMBERS(krb5_address.contents,,,[$headers])
AC_CHECK_MEMBERS(krb5_authdata.len,,,[$headers])
AC_CHECK_MEMBERS(krb5_authdata.val,,,[$headers])
AC_CHECK_MEMBERS(krb5_authdata.ad_type,,,[$headers])
AC_CHECK_MEMBERS(krb5_authdata.length,,,[$headers])
AC_CHECK_MEMBERS(krb5_authdata.contents,,,[$headers])
AC_CHECK_MEMBERS(krb5_prompt.prompt_type,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.length,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.data,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.realm.data,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.realm.length,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.name.name_string.len,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.name.name_string.val,,,[$headers])
AC_CHECK_MEMBERS(krb5_principal_data.realm,,,[$headers])
AC_CHECK_MEMBERS(krb5_ticket.client,,,[$headers])
AC_CHECK_MEMBERS(krb5_ticket.enc_part2,,,[$headers])

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

AC_ARG_WITH(keyutils,
[AC_HELP_STRING(--without-keyutils,[Disable support for setting permissions on keyring credential caches (default is AUTO).])],
	    keyutils=$withval,
	    keyutils=AUTO)
if test x$keyutils != xno ; then
	AC_CHECK_HEADERS(keyutils.h)
	LIBSsave="$LIBS"
	LIBS=
	AC_CHECK_FUNC(keyctl_chown,,[AC_CHECK_LIB(keyutils,keyctl_chown)])
	unset ac_cv_func_keyctl_chown
	AC_CHECK_FUNCS(keyctl_chown)
	if test x$ac_cv_header_keyutils_h = xyes && \
	   test x$ac_cv_func_keyctl_chown = xyes ; then
		KEYUTILS_LIBS="$LIBS"
		AC_DEFINE(HAVE_KEYUTILS,1,[Define if you have libkeyutils.])
	else
		if test x$keyutils = xyes ; then
			AC_MSG_ERROR(keyutils library not found)
		else
			AC_MSG_WARN(keyutils library not found)
		fi
	fi
	KEYUTILS_LIBS="$LIBS"
	LIBS="$LIBSsave"
	AC_SUBST(KEYUTILS_LIBS)
fi

AC_MSG_CHECKING(whether to link directly with libpam)
AC_ARG_WITH(libpam,
[AC_HELP_STRING(--without-libpam,[Refrain from linking directly with libpam.])],
	    [with_libpam=$withval],
	    [with_libpam=yes])
if test "$with_libpam" != no ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(WITH_DIRECT_LIBPAM,[test "$with_libpam" != no])

AC_ARG_ENABLE(default-realm,AC_HELP_STRING([--enable-default-realm=REALM],[last-ditch fallback realm (default is EXAMPLE.COM)]),default_realm=$enableval,default_realm=EXAMPLE.COM)
AC_DEFINE_UNQUOTED(DEFAULT_REALM,"$default_realm",[Define to the realm name which will be used if no realm is given as a parameter and none is given in krb5.conf.])
AC_MSG_RESULT([Using "$default_realm" as the default realm.])
AC_ARG_ENABLE(default-ccache-dir,AC_HELP_STRING([--enable-default-ccache-dir=DIRECTORY],[default directory in which ccache files will be stored (default is /tmp)]),default_ccache_dir=$enableval,default_ccache_dir=/tmp)
AC_DEFINE_UNQUOTED(DEFAULT_CCACHE_DIR,"$default_ccache_dir",[Define to the name of the directory in which ccache files will be stored by default.])
AC_ARG_ENABLE(default-ccname-template,AC_HELP_STRING([--enable-default-ccname-template=TEMPLATE],[default location to store the user's session-specific credentials (default is CCACHE_DIR/krb5cc_%U_XXXXXX)]),default_ccname_template=$enableval,default_ccname_template=FILE:%d/krb5cc_%U_XXXXXX)
AC_DEFINE_UNQUOTED(DEFAULT_CCNAME_TEMPLATE,"$default_ccname_template",[Define to the template used to generate name of the user's ccache.])
AC_MSG_RESULT([Using "$default_ccache_dir" to store ccache files.])
AC_MSG_RESULT([Using "$default_ccname_template" to store the user's ccache.])
AC_ARG_ENABLE(default-keytab-location,AC_HELP_STRING([--enable-default-keytab-location=FILE:/etc/krb5.keytab],[default location for local keys used for verifying TGTs (default is FILE:/etc/krb5.keytab)]),default_keytab=$enableval,default_keytab=FILE:/etc/krb5.keytab)
AC_DEFINE_UNQUOTED(DEFAULT_KEYTAB_LOCATION,"$default_keytab",[Define to the default location for your keytab file, which will be used for verifying TGTs.])
DEFAULT_KEYTAB="$default_keytab"
AC_SUBST(DEFAULT_KEYTAB)
AC_MSG_RESULT([Using "$default_keytab" as the default keytab.])
AC_ARG_ENABLE(default-token-strategy,AC_HELP_STRING([--enable-default-token-strategy=STRATEGY],[default list of methods pam_krb5 should attempt to use to set AFS tokens (default is v4,524,2b,rxk5)]),default_token_strategy=$enableval,default_token_strategy=[v4,524,2b,rxk5])
AC_DEFINE_UNQUOTED(DEFAULT_TOKEN_STRATEGY,"$default_token_strategy",[Define to the ordered list of methods which should be used when attempting to set AFS tokens.])
DEFAULT_TOKEN_STRATEGY="$default_token_strategy"
AC_SUBST(DEFAULT_TOKEN_STRATEGY)
AC_MSG_RESULT([Using "$default_token_strategy" as the default token-setting strategy.])

PAM_KRB5_APPNAME=pam
AC_DEFINE_UNQUOTED(PAM_KRB5_APPNAME,"$PAM_KRB5_APPNAME",[Define to the application name, which defines which appdefaults section will be expected to hold this module's configuration in krb5.conf.])
AC_SUBST(PAM_KRB5_APPNAME)

AC_DEFINE(PAM_KRB5_MAYBE_CONST,[const],[Define to the proper qualifier (either const or nothing) for your PAM implementation.])
AC_DEFINE(PASSWORD_CHANGE_PRINCIPAL,["kadmin/changepw"],[Define to the principal name of the password-changing service for any given realm.])

if test x$GCC = xyes ; then
	AC_ARG_ENABLE(extra-warnings,AC_HELP_STRING([--enable-extra-warnings],[enable additional GCC-specific warnings (default is no)]),extra_warnings=$enableval,extra_warnings=no)
	if test x$extra_warnings = xyes ; then
		CFLAGS="$CFLAGS -Wall -Wextra -Wimplicit -Wunused -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wcast-align"
	fi
	AC_ARG_ENABLE(Werror,AC_HELP_STRING([--enable-Werror],[enable -Werror as a compile flag (default is no)]),enable_Werror=$enableval,enable_Werror=no)
	if test x$enable_Werror = xyes ; then
		CFLAGS="$CFLAGS -Werror"
	fi
fi
if test x$with_gnu_ld = xyes ; then
	if test x$GCC = xyes ; then
		SYMBOLIC_LINKER_FLAG="-Wl,-Bsymbolic"
	else
		SYMBOLIC_LINKER_FLAG="-Bsymbolic"
	fi
	AC_MSG_RESULT([will link using "$SYMBOLIC_LINKER_FLAG" to reduce conflicts])
fi
AC_SUBST(SYMBOLIC_LINKER_FLAG)

AH_VERBATIM([PAM_KRB5_GNUC_PRINTF_DEFINED],
[/* Add attribute tags to help spot format specifier problems. */
 #ifdef __GNUC__
 #define PAM_KRB5_GNUC_PRINTF(__x,__y) __attribute__((format(printf,__x,__y)))
 #else
 #define PAM_KRB5_GNUC_PRINTF(__x,__y)
 #endif
])

AC_MSG_CHECKING([for location to install module and helpers])
pam_krb5_securitydir=`echo $libdir/security | sed s,^NONE,${exec_prefix},`
pam_krb5_securitydir=`eval echo $pam_krb5_securitydir | sed s,^NONE,${prefix},`
pam_krb5_securitydir=`eval echo $pam_krb5_securitydir | sed -e s,^NONE,${ac_default_prefix}, -e s,^//,/,g`
AC_DEFINE_UNQUOTED(SECURITYDIR,"$pam_krb5_securitydir",[The location where the pam_krb5 module will be installed.])
SECURITYDIR="$pam_krb5_securitydir"
AC_SUBST(SECURITYDIR)
pam_krb5_pkgsecuritydir=`eval echo $pam_krb5_securitydir/$PACKAGE`
AC_DEFINE_UNQUOTED(PKGSECURITYDIR,"$pam_krb5_pkgsecuritydir",[The location of pam_krb5 helpers.])
AC_MSG_RESULT([modules in $pam_krb5_securitydir, helpers in $pam_krb5_pkgsecuritydir])

# Set up to make Heimdal-specific PKINIT man page sections variable.
if test x$ac_cv_func_krb5_get_init_creds_opt_set_pkinit = xyes ; then
	MAN_HPKINIT=""
	NO_MAN_HPKINIT=".\\\" "
else
	NO_MAN_HPKINIT=""
	MAN_HPKINIT=".\\\" "
fi
AC_SUBST(NO_MAN_HPKINIT)
AC_SUBST(MAN_HPKINIT)

# Provide a means of setting the location of the user's PKINIT identity
# information.
AC_ARG_WITH(default-pkinit-identity,
[AC_HELP_STRING(--with-default-pkinit-identity="PKCS11:/usr/$LIB/pkcs11.so",[Set the default value of the "pkinit-identity" option (default is "") (Heimdal).])],
	    [DEFAULT_PKINIT_IDENTITY="$withval"
	     AC_MSG_RESULT(Using default PKINIT identity "$withval".)],
	    [DEFAULT_PKINIT_IDENTITY=""])
AC_DEFINE_UNQUOTED(DEFAULT_PKINIT_IDENTITY,"$DEFAULT_PKINIT_IDENTITY",[Set to the default location of the client's private key and PKI certificate.])
AC_SUBST(DEFAULT_PKINIT_IDENTITY)
# Provide a means of setting preauthentication options.
AC_ARG_WITH(default-preauth-options,
[AC_HELP_STRING([--with-default-preauth-options="X509_user_identity=PKCS11:/usr/$LIB/pkcs11.so"],[Set the default preauthentication options passed to libkrb5 (default is "") (MIT).])],
	    [DEFAULT_PREAUTH_OPTIONS="$withval"
	     AC_MSG_RESULT(Using default preauthentication options "$withval".)],
	    [DEFAULT_PREAUTH_OPTIONS=""])
AC_DEFINE_UNQUOTED(DEFAULT_PREAUTH_OPTIONS,"$DEFAULT_PREAUTH_OPTIONS",[Set to the default list of preauthentication options.])
AC_SUBST(DEFAULT_PREAUTH_OPTIONS)

# Set up to make MIT-specific PA man page sections variable.
if test x$ac_cv_func_krb5_get_init_creds_opt_set_pa = xyes ; then
	MAN_MPREAUTH=""
	NO_MAN_MPREAUTH=".\\\" "
else
	NO_MAN_MPREAUTH=""
	MAN_MPREAUTH=".\\\" "
fi
AC_SUBST(NO_MAN_MPREAUTH)
AC_SUBST(MAN_MPREAUTH)

# Set up to make MIT-specific krb5_aname_to_localname man page section variable.
if test x$ac_cv_func_krb5_aname_to_localname = xyes ; then
	MAN_MANAME=""
	NO_MAN_MANAME=".\\\" "
else
	NO_MAN_MANAME=""
	MAN_MANAME=".\\\" "
fi
AC_SUBST(NO_MAN_MANAME)
AC_SUBST(MAN_MANAME)

TESTDIR=`cd ${ac_top_builddir:-.}; /bin/pwd`/tests
TESTHOST=`hostname`
AC_SUBST(TESTDIR)
AC_SUBST(TESTHOST)
AC_SUBST(default_ccache_dir)
AC_SUBST(default_ccname_template)

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.17])

AH_VERBATIM([_ZZENABLE_NLS],
[
 /* Why Y_? Because if we somehow pull in OpenSSL's <des_old.h>, it'll
    undefine _ out from under us. */
 #ifdef ENABLE_NLS
 #include <libintl.h>
 #define Y_(msgid) dgettext(PACKAGE, msgid)
 #define N_(msgid) msgid
 #else
 #define Y_(msgid) (msgid)
 #define N_(msgid) msgid
 #endif /* ENABLE_NLS */
])

AC_CONFIG_HEADER(config.h)
AC_OUTPUT([
Makefile
src/Makefile
src/afs5log.1
src/pagsh.1
src/pam_newpag.5
src/pam_newpag.8
src/pam_krb5.5
src/pam_krb5.8
src/pam_krb5_storetmp.8
tests/Makefile
tests/config/Makefile
tests/config/krb5.conf
tests/config/kdc.conf
tests/config/krb.conf
tests/kdc/Makefile
tests/testenv.sh
tests/testenv-krbldap.sh
tests/tools/Makefile
po/Makefile.in
])
