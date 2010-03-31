#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking ability to get v4 credentials.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo With krb4 via krb524.
test_run -auth -setcred $test_principal -run klist_4 $pam_krb5 $test_flags not_renewable not_proxiable not_forwardable krb4_convert krb4_convert_524 no_krb4_use_as_req -- foo

echo "";echo With krb4 via kdc.
test_run -auth -setcred $test_principal -run klist_4 $pam_krb5 $test_flags not_renewable not_proxiable not_forwardable krb4_convert no_krb4_convert_524 krb4_use_as_req -- foo
