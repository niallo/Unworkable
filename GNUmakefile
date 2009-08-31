#
# Copyright (c) 2008 Michael Stapelberg <michael+unworkable@stapelberg.de>
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

CC?= cc
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -g -ggdb
CFLAGS+= -Iopenbsd-compat

PROG=unworkable
SRCS=announce.c bencode.c buf.c ctl_server.c main.c network.c \
     parse.y progressmeter.c scheduler.c torrent.c trace.c util.c xmalloc.c
LIBS=-levent -lcrypto -lpthread
UNAME=$(shell uname)
ifneq (, $(filter Linux GNU GNU/%, $(UNAME)))
SRCS+=openbsd-compat/strlcpy.c
SRCS+=openbsd-compat/strlcat.c
SRCS+=openbsd-compat/sha1.c
SRCS+=openbsd-compat/strtonum.c
CFLAGS+=-DNO_STRLCPY
CFLAGS+=-DNO_STRLCAT
CFLAGS+=-DNO_STRTONUM
else
ifeq ($(UNAME),sunos)
SRCS+=openbsd-compat/err.c
SRCS+=openbsd-compat/errx.c
SRCS+=openbsd-compat/warn.c
SRCS+=openbsd-compat/warnx.c
SRCS+=openbsd-compat/verr.c
SRCS+=openbsd-compat/verrx.c
SRCS+=openbsd-compat/vwarnx.c
SRCS+=openbsd-compat/vwarn.c
CFLAGS+=-DNO_ERR
CFLAGS+=-I/usr/local/ssl/include
LIBS+=-L/usr/local/ssl/lib
LIBS+=-L/usr/ucblib
LIBS+=-lsocket
LIBS+=-lnsl
LIBS+=-lucb
else
ifeq ($(UNAME),Darwin)
LIBS+=-L/opt/local/lib
CFLAGS+=-I/opt/local/include
endif
endif
endif
OBJS=$(patsubst %.y,%.o,$(patsubst %.c,%.o,${SRCS}))
MAN=unworkable.1

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${LDFLAGS} ${OBJS} ${LIBS}

clean:
	rm -rf *.o openbsd-compat/*.o *.so ${PROG} y.tab.h

distclean: clean
	rm -rf unworkable

libunworkable.so:
	CFLAGS=-fPIC make unworkable
	${CC} -o $@ ${LDFLAGS} -shared ${OBJS} ${LIBS}

install:
	install -m 755 -d $(DESTDIR)/usr/bin
	install -m 755 -d $(DESTDIR)/usr/share/man/man1
	install -m 755 ${PROG} $(DESTDIR)/usr/bin
	install -m 644 ${MAN} $(DESTDIR)/usr/share/man/man1

install-library:
	install -m 755 -d /usr/local/lib
	install -m 755 -d /usr/local/include/unworkable/sys
	install -m 755 libunworkable.so /usr/local/lib
	install -m 644 unworkable.h /usr/local/include/unworkable
	install -m 644 openbsd-compat/sys/tree.h /usr/local/include/unworkable/sys
	install -m 644 unworkable.pc /usr/local/lib/pkgconfig/unworkable.pc
