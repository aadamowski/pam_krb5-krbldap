securitydir = $(libdir)/security
security_LTLIBRARIES = pam_krb5.la
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
	options.c \
	options.h \
	prompter.c \
	prompter.h \
	stash.c \
	stash.h \
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
