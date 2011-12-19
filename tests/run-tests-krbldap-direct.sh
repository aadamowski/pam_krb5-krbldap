#!/bin/sh

export LD_LIBRARY_PATH=/var/soft/PAM/usr/lib
export KRB5_TRACE=/dev/stdout
TESTROOTDIR=$(dirname $0)
$TESTROOTDIR/tools/pam_harness -auth alice $TESTROOTDIR/../src/.libs/pam_krb5.so  ignore_afs -- bar 2>&1
