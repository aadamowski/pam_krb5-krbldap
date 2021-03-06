#!/bin/sh

. $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo Renewable lifetime 0.
test_run -auth -setcred $test_principal -run klist_t $pam_krb5 $test_flags proxiable forwardable not_addressless renew_lifetime=0 -- foo
