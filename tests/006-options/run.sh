#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo FPRI
test_run -auth -setcred $test_principal -run klist_f $pam_krb5 $test_flags renew_lifetime=3600 proxiable forwardable -- foo
