#!/usr/bin/python
# Author: Omar Santos @santosomar
# version 1.0
# This is a quick demonstration on how to create a
# snifffer (packet capture script) using python.
#####################################################################

from __future__ import print_function
import socket
 
#create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# receive a packet
while True:

   # print output on terminal
   print(s.recvfrom(65565))
