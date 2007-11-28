# scons (http://www.scons.org) build for non-OpenBSD systems
# on OpenBSD, just type 'make'.
# $Id: SConstruct,v 1.6 2007-11-28 21:52:46 niallo Exp $

SRCS = ['bencode.c', 'buf.c', 'main.c', 'network.c', 'parse.y', 'progressmeter.c', \
        'torrent.c', 'trace.c', 'util.c', 'xmalloc.c']
LIBS =  ['event', 'crypto']
LIBPATH = [ '/usr/lib', '/usr/local/lib' ]
CPPPATH = ['/usr/include', '/usr/local/include' ]
CCFLAGS = ['-Wall', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wmissing-declarations', '-Wshadow', '-Wpointer-arith', '-Wcast-qual', '-Wsign-compare', '-g', '-ggdb']

env = Environment(LIBPATH=LIBPATH)
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

if not conf.CheckCHeader('sys/queue.h') or not conf.CheckCHeader('sys/tree.h') \
	or not conf.CheckCHeader('sha1.h'):
	print "Missing some headers, using bundled includes"
	CPPPATH.append('openbsd-compat/')

if not conf.CheckFunc('strlcpy'):
	print "No system strlcpy found.  Using bundled version"
	SRCS.append('openbsd-compat/strlcpy.c')
	conf.env.Append(CCFLAGS = '-DNO_STRLCPY')
	CCFLAGS.append('-DNO_STRLCPY')

if not conf.CheckFunc('strlcat'):
	print "No system strlcat found.  Using bundled version"
	SRCS.append('openbsd-compat/strlcat.c')
	CCFLAGS.append('-DNO_STRLCAT')

if not conf.CheckFunc('strtonum'):
	print "No system strtonum found.  Using bundled version"
	SRCS.append('openbsd-compat/strtonum.c')
	CCFLAGS.append('-DNO_STRTONUM')

if not conf.CheckFunc('SHA1Update'):
	print "No system SHA1Update found.  Using bundled version"
	SRCS.append('openbsd-compat/sha1.c')

env = conf.Finish()

Program('unworkable', SRCS, LIBS=LIBS, LIBPATH=LIBPATH, CPPPATH=CPPPATH, CCFLAGS=CCFLAGS)
