#!/bin/sh

source $testdir/testenv.sh

echo "";echo Expiring password.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null

echo "";echo Fail: incorrect password.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account $test_principal $pam_krb5 $test_flags -- bar

echo "";echo Succeed: correct password, warn about expiration.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account $test_principal $pam_krb5 $test_flags -- foo bar bar

echo "";echo Succeed: correct password, do not warn about expiration.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account $test_principal $pam_krb5 $test_flags no_warn -- foo

echo "";echo Succeed: correct password, expired, change.
kadmin.local -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
kadmin.local -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account -chauthtok -setcred -session $test_principal $pam_krb5 $test_flags no_warn -- foo foo bar bar baz baz
