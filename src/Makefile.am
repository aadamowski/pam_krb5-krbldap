securitydir = $(libdir)/security
security_LTLIBRARIES = pam_krb5.la
pkgsecuritydir = $(libdir)/security/$(PACKAGE)
pkgsecurity_PROGRAMS = pam_krb5_storetmp
EXTRA_DIST = pam_krb5.5  pam_krb5.8
man_MANS = pam_krb5.5 pam_krb5.8
pam_krb5_la_LDFLAGS = -avoid-version -export-dynamic -module -export-symbols-regex 'pam_sm.*'
pam_krb5_la_SOURCES = \
	conv.c \
	conv.h \
	init.c \
	init.h \
	initopts.c \
	initopts.h \
	items.c \
	items.h \
	log.c \
	log.h \
	map.c \
	map.h \
	options.c \
	options.h \
	prompter.c \
	prompter.h \
	stash.c \
	stash.h \
	storetmp.c \
	storetmp.h \
	tokens.c \
	tokens.h \
	userinfo.c \
	userinfo.h \
	xstr.c \
	xstr.h \
	v5.c \
	v5.h \
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
