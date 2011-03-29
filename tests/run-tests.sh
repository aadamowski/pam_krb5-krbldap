#!/bin/sh

testdir=`dirname "$0"`
testdir=`cd "$testdir" ; pwd`
export testdir

. $testdir/testenv.sh
echo "Running tests using test principal \"$test_principal\"".
echo "Running tests using KDC on \"$test_host\"".
getent hosts "$test_host"

# Tell the caller where the binaries are.
test -n "$krb5kdc" && echo Using krb5kdc binary: $krb5kdc
test -n "$krb524d" && echo Using krb524d binary: $krb524d
test -n "$kadmind" && echo Using kadmind binary: $kadmind
test -n "$kadmin"  && echo Using kadmin.local binary: $kadmin

# Run each test with clear log files and a fresh copy of the KDC and kadmind,
# and a fresh 524d if available.
for test in ${@:-"$testdir"/0*} ; do
	if ! test -s $test/run.sh ; then
		continue
	fi
	if ! $test_addresses ; then
		if test -r $test/uses_addresses ; then
			echo Skipping address manipulating test `basename "$test"`.
			continue
		fi
	fi
	if ! $test_krb4 ; then
		if test -r $test/uses_v4 ; then
			echo Skipping v4-specific test `basename "$test"`.
			continue
		fi
	fi
	echo -n `basename "$test"` ..." "
	test_kdcinitdb
	test_kdcprep
	meanwhile "$run_kdc" "$run_kadmind" "$run_krb524d" "$test/run.sh" > $test/stdout 2> $test/stderr
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
