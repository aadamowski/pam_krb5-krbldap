SUBDIRS = config tools kdc

EXTRA_DIST = run-tests.sh testenv.sh.in pwhelp.txt \
	001-pambasic/run.sh \
	001-pambasic/stderr.expected \
	001-pambasic/stdout.expected \
	002-pamchpw-wrongpw/run.sh \
	002-pamchpw-wrongpw/stderr.expected \
	002-pamchpw-wrongpw/stdout.expected \
	003-pamchpw-warn/run.sh \
	003-pamchpw-warn/stderr.expected \
	003-pamchpw-warn/stdout.expected \
	004-pamchpw-nowarn/run.sh \
	004-pamchpw-nowarn/stderr.expected \
	004-pamchpw-nowarn/stdout.expected \
	005-pamchpw-success/run.sh \
	005-pamchpw-success/stderr.expected \
	005-pamchpw-success/stdout.expected \
	006-options-fpri/run.sh \
	006-options-fpri/stderr.expected \
	006-options-fpri/stdout.expected \
	007-options-none/run.sh \
	007-options-none/stderr.expected \
	007-options-none/stdout.expected \
	008-options-noaddr/run.sh \
	008-options-noaddr/stderr.expected \
	008-options-noaddr/stdout.expected \
	009-options-addrs/run.sh \
	009-options-addrs/stderr.expected \
	009-options-addrs/stdout.expected \
	010-options-moreaddrs/run.sh \
	010-options-moreaddrs/stderr.expected \
	010-options-moreaddrs/stdout.expected \
	010-options-moreaddrs/uses_addresses \
	011-options-nov4/run.sh \
	011-options-nov4/stderr.expected \
	011-options-nov4/stdout.expected \
	011-options-nov4/uses_v4 \
	012-options-renew0/run.sh \
	012-options-renew0/stderr.expected \
	012-options-renew0/stdout.expected \
	013-options-renew/run.sh \
	013-options-renew/stderr.expected \
	013-options-renew/stdout.expected \
	014-options-defccdir/run.sh \
	014-options-defccdir/stderr.expected \
	014-options-defccdir/stdout.expected \
	015-options-ccdir/run.sh \
	015-options-ccdir/stderr.expected \
	015-options-ccdir/stdout.expected \
	016-options-banner/run.sh \
	016-options-banner/stderr.expected \
	016-options-banner/stdout.expected \
	017-options-help/run.sh \
	017-options-help/stderr.expected \
	017-options-help/stdout.expected \
	018-krb4/run.sh \
	018-krb4/stderr.expected \
	018-krb4/stdout.expected \
	018-krb4/uses_v4 \
	019-pamchpw-prompt-wrongpw/run.sh \
	019-pamchpw-prompt-wrongpw/stderr.expected \
	019-pamchpw-prompt-wrongpw/stdout.expected \
	020-pamchpw-prompt-success/run.sh \
	020-pamchpw-prompt-success/stderr.expected \
	020-pamchpw-prompt-success/stdout.expected

check: all testenv.sh
	$(srcdir)/run-tests.sh
