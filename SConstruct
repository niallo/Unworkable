# scons (http://www.scons.org) build for non-OpenBSD systems
# on OpenBSD, just type 'make'.
# $Id: SConstruct,v 1.13 2007-12-09 05:19:16 niallo Exp $

import sys

SRCS = ['announce.c', 'bencode.c', 'buf.c', 'main.c', 'network.c', 'parse.y', 'progressmeter.c', \
        'scheduler.c', 'torrent.c', 'trace.c', 'util.c', 'xmalloc.c']
LIBS =  ['event', 'crypto']
LIBPATH = ['/usr/lib', '/usr/local/lib']
CPPPATH = ['/usr/include', '/usr/local/include']
CCFLAGS = ['-Wall', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wmissing-declarations', '-Wshadow', '-Wpointer-arith', '-Wcast-qual', '-Wsign-compare', '-g', '-ggdb']

# Assume this is Solaris with packages from www.sunfreeware.com
if sys.platform.startswith('sunos'):
	SRCS.append('openbsd-compat/err.c')
	SRCS.append('openbsd-compat/errx.c')
	SRCS.append('openbsd-compat/warn.c')
	SRCS.append('openbsd-compat/warnx.c')
	SRCS.append('openbsd-compat/verr.c')
	SRCS.append('openbsd-compat/verrx.c')
	SRCS.append('openbsd-compat/vwarnx.c')
	SRCS.append('openbsd-compat/vwarn.c')
	CPPPATH.append('/usr/local/ssl/include')
	CPPPATH.append('openbsd-compat/')
	LIBPATH.append('/usr/local/ssl/lib')
	LIBPATH.append('/usr/ucblib')
	LIBS.append('socket')
	LIBS.append('nsl')
	LIBS.append('ucb')
	CCFLAGS.append('-DNO_ERR')

# Assume this is Mac OS X with macports, so stuff is under /opt
elif sys.platform.startswith('darwin'):
	LIBPATH.append('/opt/local/lib')
	CPPPATH.append('/opt/local/include')

env = Environment(LIBPATH=LIBPATH, CPPPATH=CPPPATH)
conf = Configure(env)

if not conf.CheckType('u_int8_t'):
	CCFLAGS.append('-Du_int8_t=unsigned char')

if not conf.CheckType('u_int32_t'):
	CCFLAGS.append('-Du_int32_t=unsigned int')

if not conf.CheckType('u_int64_t'):
	CCFLAGS.append('-Du_int64_t=unsigned long long')

if not conf.CheckType('int64_t'):
	CCFLAGS.append('-Dint64_t=long long')

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

if not conf.CheckFunc('getaddrinfo'):
	print "No system getaddrinfo() found.  Using bundled version"
	SRCS.append('openbsd-compat/getaddrinfo.c')
	CCFLAGS.append('-DNO_GETADDRINFO')

if not conf.CheckLib('crypto'):
	print "OpenSSL crypto library not found on your system.  You can get it at http://www.openssl.org"
	Exit(1)

if not conf.CheckLib('event'):
	print "Libevent not found on your system.  You can get it at http://monkey.org/~provos/libevent/"
	Exit(1)


env = conf.Finish()

env.Program('unworkable', SRCS, LIBS=LIBS, LIBPATH=LIBPATH, CPPPATH=CPPPATH, CCFLAGS=CCFLAGS)
