#!/usr/local/bin/python

# $Id: conn.py,v 1.2 2007-12-11 07:29:44 niallo Exp $
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
import threading
import time

HOST = 'localhost'
PORT = 6099

def usage():
	print >> sys.stderr, "%s: [-h host] [-p port]" %(sys.argv[0])
	os._exit(1)

def status(ctl):
	print "peers: %s pieces: %s/%s downloaded: %s" %(len(ctl.peers), len(ctl.pieces), ctl.num_pieces, ctl.torrent_bytes + ctl.bytes)

class CTLconnection(threading.Thread):
	''' Connection to the control server, runs in its own thread '''
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.num_peers = 0
		self.num_pieces = 0
		self.torrent_size = 0
		self.torrent_bytes = 0
		self.pieces = []
		self.peers = []
		self.bytes = 0
		self.done = False
		self._socket = None
		self._f = None
		threading.Thread.__init__(self)
	def stop(self):
		self._f.close()
		self._s.close()
		self._done = True
	def run(self):
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.connect((self.host, self.port))
		self._f = self._socket.makefile()

		for l in self._f:
			try:
				d = l.strip().split(':', 1)
			except:
				# ignore malformed line
				continue
			if d[0] == 'num_peers':
				if not isinstance(d[1], int):
					continue
				self.num_peers = int(d[1])
			elif d[0] == 'num_pieces':
				self.num_pieces = int(d[1])
			elif d[0] == 'torrent_size':
				self.torrent_size = int(d[1])
			elif d[0] == 'torrent_bytes':
				self.torrent_bytes = int(d[1])
			elif d[0] == 'pieces':
				try:
					new_pieces = d[1].split(',')
					new_pieces.sort()
					self.pieces = new_pieces
				except:
					# no pieces yet
					continue
			elif d[0] == 'bytes':
				self.bytes = int(d[1])
			elif d[0] == 'peers':
				try:
					new_peers = d[1].split(',')
					new_peers.sort()
					self.peers = new_peers
				except:
					# no peers yet
					continue
			else:
				print "unkown message: %s" %(l)
		self._f.close()
		self._s.close()
		self.done = True


try:
	opts, args = getopt.getopt(sys.argv[1:], "h:p:")
except getopt.GetoptError:
	usage()

for o, a in opts:
	if o == "-h":
		HOST = a
	if o == "-p":
		PORT = int(a)

ctl = CTLconnection(HOST, PORT)
ctl.start()
while not ctl.done:
	status(ctl)
	time.sleep(5)
