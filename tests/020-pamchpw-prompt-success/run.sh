#!/bin/sh

source $testdir/testenv.sh

echo "";echo Succeed: correct password, expired, change.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire now '$test_principal 2> /dev/null > /dev/null
test_settle
test_run -auth -account -setcred -session $test_principal $pam_krb5 $test_flags chpw_prompt -- foo bar bar
