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
# $Id: Makefile,v 1.20 2007-08-02 23:18:45 niallo Exp $

CC?= cc
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -g -ggdb

#
# Uncomment if you like to use Boehm's garbage collector (/usr/ports/devel/boehm-gc).
#LDFLAGS+=                -L/usr/local/lib -lgc
#DPADD+=                /usr/local/lib/libgc.a
#CFLAGS+=               -DUSE_BOEHM_GC -DGC_DEBUG -DFIND_LEAK -I/usr/local/include
# You can also use Boehm's garbage collector as a means to find leaks.
#  # export GC_FIND_LEAK=1

PROG= unworkable

SRCS= bencode.c buf.c main.c network.c parse.y progressmeter.c torrent.c trace.c util.c xmalloc.c
OBJS= ${SRCS:N*.h:N*.sh:R:S/$/.o/g}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o ${.TARGET} ${LDFLAGS} -levent -lcrypto ${OBJS}

clean:
	rm -rf *.o ${PROG} y.tab.h
