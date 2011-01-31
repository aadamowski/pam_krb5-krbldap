#!/bin/sh

source $testdir/testenv.sh

echo "";echo Expiring password.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null

echo "";echo Succeed: correct password, do not warn about expiration.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_run -auth -account $test_principal $pam_krb5 $test_flags no_warn -- foo
