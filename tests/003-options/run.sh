#!/bin/sh

source $testdir/testenv.sh

echo "";echo Checking handling of options.
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo "";echo FPRI
test_run -auth -setcred $test_principal -run klist_f $pam_krb5 $test_flags renew_lifetime=3600 proxiable forwardable -- foo

echo "";echo I
test_run -auth -setcred $test_principal -run klist_f $pam_krb5 $test_flags renew_lifetime=0 not_proxiable not_forwardable -- foo

echo "";echo No addresses.
test_run -auth -setcred $test_principal -run klist_a0 $pam_krb5 $test_flags proxiable forwardable addressless -- foo

echo "";echo With local addresses.
test_run -auth -setcred $test_principal -run klist_a $pam_krb5 $test_flags proxiable forwardable not_addressless -- foo

echo "";echo With local and extra addresses.
test_run -auth -setcred $test_principal -run klist_a $pam_krb5 $test_flags proxiable forwardable hosts="1.2.3.4" -- foo

echo "";echo Without krb4.
test_run -auth -setcred $test_principal -run klist_4 $pam_krb5 $test_flags proxiable forwardable not_addressless no_krb4_convert_kdc no_krb4_use_as_req -- foo

echo "";echo Renewable lifetime 0.
test_run -auth -setcred $test_principal -run klist_t $pam_krb5 $test_flags proxiable forwardable not_addressless renew_lifetime=0 -- foo

echo "";echo Renewable lifetime 1 hour.
test_run -auth -setcred $test_principal -run klist_t $pam_krb5 $test_flags proxiable forwardable not_addressless renew_lifetime=3600 -- foo

echo "";echo Default ccache directory.
test_run -auth -setcred $test_principal -run klist_c $pam_krb5 $test_flags -- foo

echo "";echo Ccache directory = testdir/kdc.
test_run -auth -setcred $test_principal -run klist_c $pam_krb5 $test_flags ccache_dir=${testdir}/kdc -- foo

echo "";echo Banner = K3RB3R05 S
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
test_run -chauthtok $test_principal $pam_krb5 $test_flags banner="K3RB3R05 S" -- foo bar bar

echo "";echo Password-change Help Text
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
test_run -chauthtok $test_principal $pam_krb5 $test_flags pwhelp=$testdir/pwhelp.txt -- foo bar bar
