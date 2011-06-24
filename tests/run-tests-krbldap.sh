#!/bin/sh

testdir=`dirname "$0"`
testdir=`cd "$testdir" ; pwd`
export testdir

. $testdir/testenv-krbldap.sh
echo "Running tests using test principal \"$test_principal\"".
echo "Running tests using KDC on \"$test_host\"".
getent hosts "$test_host"


# Run each test with clear log files and a fresh copy of the KDC and kadmind,
# and a fresh 524d if available.
for test in ${@:-"$testdir"/krbldap-tests/0*} ; do
	if ! test -s $test/run.sh ; then
		continue
	fi
	echo -n `basename "$test"` ..." "
	meanwhile "$test/run.sh" > $test/stdout 2> $test/stderr
	if test -s $test/stdout.expected ; then
		if ! cmp -s $test/stdout.expected $test/stdout ; then
			echo ""
			diff -u $test/stdout.expected $test/stdout | sed "s|$testdir/||g"
			echo "Test $test stdout unexpected error!"
			exit 1
		fi
		if ! cmp -s $test/stderr.expected $test/stderr ; then
			echo ""
			diff -u $test/stderr.expected $test/stderr | sed "s|$testdir/||g"
			echo "Test $test stderr unexpected error!"
			exit 1
		fi
	fi
	echo OK
done
