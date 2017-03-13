#!/usr/bin/python

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) != 3:
    print "Usage ./FW_detect.py [Target-IP] [Target Port]"
    print ""

