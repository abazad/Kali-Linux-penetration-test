#!/usr/bin/python

import logging 
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) !=2:
	print "Usage ./UDP_ping.py [/24 network address]"
	print "Example ./UDP_ping.py 172.16.36.0"
	print "Example will perform an UDP detect of the 172.16.36.0"
	sys.exit()
	
address = str(sys.argv[1])
prefix = address.split('.')[0] + '.' + address.split('.')[1] + '.' + address.split('.')[2] + '.'


for addr in range(1,254):
	response = sr1(IP(dst=prefix+str(addr))/UDP(dport=33333),timeout=0.1,verbose=0)
	try:
		if int(response[IP].proto) == 1:
			print prefix+str(addr)
	except:
		pass
