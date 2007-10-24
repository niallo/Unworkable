# scons (http://www.scons.org) build for non-OpenBSD systems
# on OpenBSD, just type 'make'.
# $Id: SConstruct,v 1.3 2007-10-24 22:06:28 niallo Exp $

SRCS = ['bencode.c', 'buf.c', 'main.c', 'network.c', 'parse.y', 'progressmeter.c', \
        'torrent.c', 'trace.c', 'util.c', 'xmalloc.c']
LIBS=  ['event', 'crypto']

Program('unworkable', SRCS, LIBS=LIBS)
