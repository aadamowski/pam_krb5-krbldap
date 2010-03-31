#!/bin/sh

testdir=`dirname "$0"`
testdir=`cd "$testdir" ; pwd`
export testdir

source $testdir/testenv.sh

# Start the KDC and 524 daemon, if we have one.
test_kdcstart

# First, a wrong password, then the right one, then a wrong one.
for test in ${@:-"$testdir"/0*} ; do
	if ! test -s $test/run.sh ; then
		continue
	fi
	if ! $test_krb4 ; then
		if test -r $test/uses_v4 ; then
			echo Skipping v4-specific test `basename "$test"`.
			continue
		fi
	fi
	echo -n `basename "$test"` ..." "
	$test/run.sh > $test/stdout 2> $test/stderr
	if test -s $test/stdout.expected ; then
		if ! cmp $test/stdout.expected $test/stdout ; then
			echo ""
			diff -u $test/stdout.expected $test/stdout | sed "s|$testdir/||g"
			exit 1
		fi
		if ! cmp $test/stderr.expected $test/stderr ; then
			echo ""
			diff -u $test/stderr.expected $test/stderr | sed "s|$testdir/||g"
			exit 1
		fi
	fi
	echo OK
done

# Stop the KDC.
test_kdcstop
