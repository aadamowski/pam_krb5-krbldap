#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo Ccache directory = testdir/kdc.
test_run -auth -setcred $test_principal -run klist_c $pam_krb5 $test_flags ccache_dir=${testdir}/kdc -- foo
