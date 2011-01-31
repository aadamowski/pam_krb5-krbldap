#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo Without krb4.
test_run -auth -setcred $test_principal -run klist_4 $pam_krb5 $test_flags proxiable forwardable not_addressless no_krb4_convert_kdc no_krb4_use_as_req -- foo
