#!/bin/sh

# Zero exit code is success, non-zero is failure.
function test1 {
	echo "$1" | ./unworkable 2>&1 > /dev/null
	if [ $? -ne 0 ]
	then
		echo "failure on input: $1"
		exit 1
	fi
}

# Zero exit code is failure, non-zero is success.
function test2 {
	echo "$1" | ./unworkable 2>&1 > /dev/null
	if [ $? -eq 0 ]
	then
		echo "failure on input: $1"
		exit 1
	fi
}

test1 "li300ee"
test1 "i300ei450ei-300e"
test1 "4:hate"
