#!/bin/sh

export KRB5_TRACE=/dev/stdout
TESTROOTDIR=$(dirname $0)

KRB5_CONFIG=$(readlink -f $TESTROOTDIR/config/krb5.conf) ; export KRB5_CONFIG; echo "KRB5_CONFIG: $KRB5_CONFIG"
KRBCONFDIR=$TESTROOTDIR/config ; export KRBCONFDIR
KRB_CONF=$TESTROOTDIR/config/krb.conf ; export KRB_CONF
KRB5RCACHEDIR=$TESTROOTDIR/kdc ; export KRB5RCACHEDIR
KRB5CCNAME=/dev/bogus-missing-file ; export KRB5CCNAME
KRBTKFILE=/dev/bogus-missing-file ; export KRBTKFILE

$TESTROOTDIR/tools/pam_harness -auth alice $TESTROOTDIR/../src/.libs/pam_krb5.so  ignore_afs unsecure_for_debugging_only -- bar 2>&1
