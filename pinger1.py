#!/usr/bin/python

import logging 
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) !=2:
	print "Usage ./pinger1.py [/24 network address]"
	print "Example ./pinger1.py 172.16.36.0"
	print "Example will perform an ICMP scan of the 172.16.36.0"
	sys.exit()
	
address = str(sys.argv[1])
prefix = address.split('.')[0] + '.' + address.split('.')[1] + '.' + address.split('.')[2] + '.'


for addr in range(1,254):
	a = sr1(IP(dst=prefix+str(addr))/ICMP(),timeout=0.1,verbose=0)
	if a == None:
		pass
	else:
		print prefix+str(addr)
