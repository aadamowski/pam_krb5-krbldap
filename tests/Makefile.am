SUBDIRS = config tools kdc

EXTRA_DIST = run-tests.sh testenv.sh.in \
	001-pambasic/run.sh \
	001-pambasic/stdout.expected \
	001-pambasic/stderr.expected \
	002-pamchpw/run.sh \
	002-pamchpw/stdout.expected \
	002-pamchpw/stderr.expected \
	003-options/run.sh \
	003-options/stdout.expected \
	003-options/stderr.expected \
	004-krb4/run.sh \
	004-krb4/stdout.expected \
	004-krb4/stderr.expected

check: all testenv.sh
	$(srcdir)/run-tests.sh
