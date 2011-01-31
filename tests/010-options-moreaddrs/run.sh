#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo With local and extra addresses.
test_run -auth -setcred $test_principal -run klist_a $pam_krb5 $test_flags proxiable forwardable hosts="1.2.3.4" -- foo
