#!/bin/sh

source $testdir/testenv.sh

echo "";echo Expiring password.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null

echo "";echo Succeed: correct password, expired, change.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account -chauthtok -setcred -session $test_principal $pam_krb5 $test_flags no_warn -- foo foo bar bar baz baz
