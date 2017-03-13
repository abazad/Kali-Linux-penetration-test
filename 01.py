#!/usr/bin/python

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.160.139', 110))
    data = s.recv(1024)
    print data

    s.send('USER yuanfh' + '\r\n')
    data = s.recv(1024)
    print data

    s.send('PASS test\r\n')
    data = s.recv(1024)
    print data

    s.close()
    print "\n Done!"


except:
    print "Could not connect to POP3!"
