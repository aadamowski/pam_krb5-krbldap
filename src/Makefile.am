AM_CFLAGS = @KRB5_CFLAGS@ @KRB4_CFLAGS@

securitydir = $(libdir)/security
security_LTLIBRARIES = pam_krb5.la
pkgsecuritydir = $(libdir)/security/$(PACKAGE)
pkgsecurity_PROGRAMS = pam_krb5_storetmp
EXTRA_DIST = pam_krb5.5  pam_krb5.8
noinst_PROGRAMS = afs5log pagsh harness
noinst_LTLIBRARIES = libpam_krb5.la
man_MANS = pam_krb5.5 pam_krb5.8

libpam_krb5_la_SOURCES = \
	conv.c \
	conv.h \
	init.c \
	init.h \
	items.c \
	items.h \
	minikafs.c \
	minikafs.h \
	prompter.c \
	prompter.h \
	shmem.c \
	shmem.h \
	stash.c \
	stash.h \
	storetmp.c \
	storetmp.h \
	xstr.c \
	xstr.h \
	v5.c \
	v5.h
	
pam_krb5_la_LDFLAGS = -avoid-version -export-dynamic -module -export-symbols-regex 'pam_sm.*' 
pam_krb5_la_LIBADD = libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@
pam_krb5_la_SOURCES = \
	initopts.c \
	initopts.h \
	log.c \
	log.h \
	map.c \
	map.h \
	options.c \
	options.h \
	tokens.c \
	tokens.h \
	userinfo.c \
	userinfo.h \
	v4.c \
	v4.h \
	auth.c \
	acct.c \
	password.c \
	session.c \
	sly.c \
	sly.h
pam_krb5_storetmp_SOURCES = \
	pam_krb5_storetmp.c
pam_krb5_storetmp_LIBS =
pam_krb5_storetmp_LDADD = xstr.lo

afs5log_SOURCES = \
	afs5log.c \
	logstdio.c \
	logstdio.h \
	log.h
afs5log_LDADD = @PAM_LIBS@ libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@

pagsh_SOURCES = \
	pagsh.c \
	logstdio.c \
	logstdio.h \
	log.h
pagsh_LDADD = @PAM_LIBS@ libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@

harness_SOURCES = harness.c
harness_LDADD = \
	auth.lo \
	acct.lo \
	password.lo \
	session.lo \
	logstdio.lo \
	map.lo \
	initopts.lo \
	options.lo \
	userinfo.lo \
	tokens.lo \
	sly.lo \
	minikafs.lo \
	v4.lo \
	v5.lo
harness_LDADD += @PAM_LIBS@ libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@
