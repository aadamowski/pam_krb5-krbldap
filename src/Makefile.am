AM_CFLAGS = @KRB5_CFLAGS@ @KRB4_CFLAGS@

securitydir = $(libdir)/security
security_LTLIBRARIES = pam_krb5.la
pkgsecuritydir = $(libdir)/security/$(PACKAGE)
pkgsecurity_PROGRAMS = pam_krb5_storetmp
EXTRA_DIST = afs5log.1 pam_krb5.5 pam_krb5.8 pam_krb5_storetmp.8
noinst_PROGRAMS = harness shmcat
noinst_LTLIBRARIES = libpam_krb5.la
man_MANS = pam_krb5.5 pam_krb5.8 pam_krb5_storetmp.8
bin_PROGRAMS =
noinst_MANS =

if AFS
bin_PROGRAMS += afs5log
man_MANS += afs5log.1
noinst_PROGRAMS += pagsh
endif

libpam_krb5_la_SOURCES = \
	conv.c \
	conv.h \
	init.c \
	init.h \
	items.c \
	items.h \
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
	sly.lo \
	v4.lo \
	v5.lo
harness_LDADD += libpam_krb5.la @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@

shmcat_SOURCES = shmcat.c
shmcat_LDADD = logstdio.lo libpam_krb5.la @PAM_LIBS@

if AFS
pam_krb5_la_SOURCES += tokens.c
libpam_krb5_la_SOURCES += minikafs.c
harness_LDADD += minikafs.lo tokens.lo
else
libpam_krb5_la_SOURCES += noafs.c
endif
