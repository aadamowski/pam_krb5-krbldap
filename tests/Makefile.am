SUBDIRS = config tools kdc

EXTRA_DIST = run-tests.sh testenv.sh.in \
	001-pambasic/{run.sh,{stdout,stderr}.expected}
	002-pamchpw/{run.sh,{stdout,stderr}.expected}
	003-options/{run.sh,{stdout,stderr}.expected}
	004-krb4/{run.sh,{stdout,stderr}.expected}

check: all testenv.sh
	$(srcdir)/run-tests.sh
