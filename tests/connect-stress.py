import socket

HOST='127.0.0.1'
PORT=6668
for i in range(0,1000):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	s.send('blah')
	s.close()
