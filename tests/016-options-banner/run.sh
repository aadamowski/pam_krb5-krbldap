#!/bin/sh

. $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo Banner = K3RB3R05 S
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
test_run -chauthtok $test_principal $pam_krb5 $test_flags banner="K3RB3R05 S" -- foo bar bar
