#!/bin/sh

. $testdir/testenv-krbldap.sh

test_flags="$test_flags ignore_afs"

echo "test_run -auth $test_principal $pam_krbldap $test_flags -- bar"
echo ""; echo Fail: incorrect password.
test_run -auth $test_principal $pam_krbldap $test_flags -- bar

#echo ""; echo Fail: incorrect password.
#test_run -auth $test_principal $pam_krbldap $test_flags -- foolong
#
#echo ""; echo Fail: incorrect password.
#test_run -auth $test_principal $pam_krbldap $test_flags -- foolongerstill
#
#echo ""; echo Succeed: correct password.
#test_run -auth -setcred -session $test_principal $pam_krbldap $test_flags -- foo
#
#echo ""; echo Fail: cannot read password.
#test_run -auth $test_principal $pam_krbldap $test_flags use_first_pass -- foo
#
#echo ""; echo Succeed: correct password, incorrect first attempt.
#test_run -auth -setcred $test_principal $pam_krbldap $test_flags try_first_pass -- foo
#
#echo ""; echo Succeed: correct password, maybe use incorrect second attempt.
#test_run -auth -session $test_principal $pam_krbldap $test_flags -authtok foo -- bar
#
#echo ""; echo Succeed: correct password, ignore second attempt.
#test_run -auth -setcred -session $test_principal $pam_krbldap $test_flags -authtok foo use_first_pass -- bar
#
#echo ""; echo Succeed: correct password, maybe use incorrect second attempt.
#test_run -auth $test_principal $pam_krbldap $test_flags -authtok foo try_first_pass -- bar
