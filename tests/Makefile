#
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
# $Id: Makefile,v 1.1 2007-05-04 00:37:13 niallo Exp $

CC?= cc
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -g -ggdb
CFLAGS+= -I../

#
# Uncomment if you like to use Boehm's garbage collector (/usr/ports/devel/boehm-gc).
#LDFLAGS+=                -L/usr/local/lib -lgc
#DPADD+=                /usr/local/lib/libgc.a
#CFLAGS+=               -DUSE_BOEHM_GC -DGC_DEBUG -DFIND_LEAK -I/usr/local/include
# You can also use Boehm's garbage collector as a means to find leaks.
#  # export GC_FIND_LEAK=1

.SUFFIXES: .o .c

.c.o:
	${CC} -I../ ${CFLAGS} -c ${.IMPSRC} -o ${.PREFIX}.o

all: network-test parser-test
	@parser-test parser-data/* > /dev/null
	
clean:
	rm -rf network-test parser-test ../*.o *.o y.tab.h

COMPILE: .USE
	${CC} ${CFLAGS} -o  ${.TARGET} ${LDFLAGS} -levent ${.ALLSRC}

NETWORK_TEST_SRCS= ../xmalloc.c ../buf.c ../bencode.c ../parse.y network-timer-test.c
network-test: ${NETWORK_TEST_SRCS:N*.h:N*.sh:R:S/$/.o/g}  COMPILE

PARSER_TEST_SRCS= ../xmalloc.c ../buf.c ../bencode.c ../parse.y parser-test.c
parser-test: ${PARSER_TEST_SRCS:N*.h:N*.sh:R:S/$/.o/g}  COMPILE
