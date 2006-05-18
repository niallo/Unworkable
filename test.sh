#!/bin/sh
# Copyright (c) 2006 Niall O'Higgins <niallo@unworkable.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: test.sh,v 1.8 2006-05-18 00:50:22 niallo Exp $

# Zero exit code is success, non-zero is failure.
function test1 {
	echo -n "$1" | ./unworkable > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "failure on input: $1"
	fi
}

# Zero exit code is failure, non-zero is success.
function test2 {
	echo -n "$1" | ./unworkable > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo "failure on input: $1"
	fi
}

test1 "li300ee"
test1 "i300ei450ei-300e"
test1 "4:h:te"
test1 "1::"
test1 "d4:dliei300ee"
test2 "d4:dlie:i300ee"
test1 "l5:spameli-350eee"
test2 "l5:spameli-350ee"
test1 "l5:spamed6:spamedi-429eeei9999999e"
