#!/usr/bin/python

import logging 
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) != 2:
	print "Usage ./pinger2.py [/24 network address]"
	print "Example ./pinger2.py 172.16.36.0"
	print "Example will perform an ECMP scan of the 172.16.36.0/24 range"
	sys.exit()
	
	
filename = str(sys.argv[1])
file = open(filename,'r')

for addr in file:
	a = sr1(IP(dst=addr.strip())/ICMP(),timeout=0.1,verbose=0)
	if a == None:
		pass
	else:
		print addr.strip()
