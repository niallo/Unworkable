# scons (http://www.scons.org) build for non-OpenBSD systems
# on OpenBSD, just type 'make'.
# $Id: SConstruct,v 1.4 2007-10-24 22:40:52 niallo Exp $

SRCS = ['bencode.c', 'buf.c', 'main.c', 'network.c', 'parse.y', 'progressmeter.c', \
        'torrent.c', 'trace.c', 'util.c', 'xmalloc.c']
LIBS=  ['event', 'crypto']

env = Environment()
conf = Configure(env)
if not conf.CheckLib('event'):
		print "Libevent not found on your system.  You can get it at http://monkey.org/~provos/libevent/"
		Exit(1)
if not conf.CheckLib('crypto'):
		print "OpenSSL crypto library not found on your system.  You can get it at http://www.openssl.org"
		Exit(1)

if not conf.CheckCHeader('openssl/bn.h'):
		print "No openssl/bn.h found.  Do you have the OpenSSL headers correctly installed?"
		Exit(1)
if not conf.CheckCHeader('openssl/dh.h'):
		print "No openssl/dh.h found.  Do you have the OpenSSL headers correctly installed?"
		Exit(1)
if not conf.CheckCHeader('openssl/engine.h'):
		print "No openssl/engine.h found.  Do you have the OpenSSL headers correctly installed?"
		Exit(1)
if not conf.CheckFunc('strlcpy'):
		print "No system strlcpy found.  Using bundled version"

if not conf.CheckFunc('strlcat'):
		print "No system strlcat found.  Using bundled version"

if not conf.CheckFunc('strtonum'):
		print "No system strtonum found.  Using bundled version"

env = conf.Finish()

Program('unworkable', SRCS, LIBS=LIBS)
