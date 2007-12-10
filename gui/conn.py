#!/usr/local/bin/python

# $Id: conn.py,v 1.1 2007-12-10 03:57:01 niallo Exp $
# Copyright (c) 2007 Niall O'Higgins <niallo@unworkable.org>
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

import getopt
import socket
import sys

HOST = 'localhost'
PORT = 6099

def usage():
	print >> sys.stderr, "%s: [-h host] [-p port]" %(sys.argv[0])
	os._exit(1)

try:
	opts, args = getopt.getopt(sys.argv[1:], "h:p:")
except getopt.GetoptError:
	usage()

for o, a in opts:
	if o == "-h":
		HOST = a
	if o == "-p":
		PORT = int(a)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
f = s.makefile()

# initial state variables
num_peers = 0
num_pieces = 0
torrent_size = 0
torrent_bytes = 0
pieces = []
peers = []
bytes = 0

def status():
	print "peers: %s pieces: %s/%s downloaded: %s" %(len(peers), len(pieces), num_pieces, torrent_bytes + bytes)

for l in f:
	try:
		d = l.strip().split(':', 1)
	except:
		# ignore malformed line
		continue
	if d[0] == 'num_peers':
		if not isinstance(d[1], int):
			continue
		num_peers = int(d[1])
	elif d[0] == 'num_pieces':
		num_pieces = int(d[1])
	elif d[0] == 'torrent_size':
		torrent_size = int(d[1])
	elif d[0] == 'torrent_bytes':
		torrent_bytes = int(d[1])
	elif d[0] == 'pieces':
		try:
			new_pieces = d[1].split(',')
			new_pieces.sort()
			pieces = new_pieces
		except:
			# no pieces yet
			continue
	elif d[0] == 'bytes':
		bytes = int(d[1])
	elif d[0] == 'peers':
		try:
			new_peers = d[1].split(',')
			new_peers.sort()
			peers = new_peers
		except:
			# no peers yet
			continue
	else:
		print "unkown message: %s" %(l)
	status()

f.close()
s.close()
