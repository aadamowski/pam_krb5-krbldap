#!/bin/sh

. $testdir/testenv.sh

test_flags="$test_flags ignore_afs"

echo ""; echo Setting password to \"foo\".
$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo ""; echo Fail: incorrect password.
test_run -auth $test_principal $pam_krb5 $test_flags -- bar

echo ""; echo Fail: incorrect password.
test_run -auth $test_principal $pam_krb5 $test_flags -- foolong

echo ""; echo Fail: incorrect password.
test_run -auth $test_principal $pam_krb5 $test_flags -- foolongerstill

echo ""; echo Succeed: correct password.
test_run -auth -setcred -session $test_principal $pam_krb5 $test_flags -- foo

echo ""; echo Fail: cannot read password.
test_run -auth $test_principal $pam_krb5 $test_flags use_first_pass -- foo

echo ""; echo Succeed: correct password, incorrect first attempt.
test_run -auth -setcred $test_principal $pam_krb5 $test_flags try_first_pass -- foo

echo ""; echo Succeed: correct password, maybe use incorrect second attempt.
test_run -auth -session $test_principal $pam_krb5 $test_flags -authtok foo -- bar

echo ""; echo Succeed: correct password, ignore second attempt.
test_run -auth -setcred -session $test_principal $pam_krb5 $test_flags -authtok foo use_first_pass -- bar

echo ""; echo Succeed: correct password, maybe use incorrect second attempt.
test_run -auth $test_principal $pam_krb5 $test_flags -authtok foo try_first_pass -- bar
