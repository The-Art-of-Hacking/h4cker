#!/usr/bin/python

from __future__ import print_function
import socket

s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
 data=s.recvfrom(65535)
 try:
  if "HTTP" in data[0][54:]:
    print("[","="*30,']')
    raw=data[0][54:]
    if "\r\n\r\n" in raw:
     line=raw.split('\r\n\r\n')[0]
     print("[*] Header Captured ")
     print(line[line.find('HTTP'):])
    else:
     print(raw)
  else:
   #print '[{}]'.format(data)
   pass
 except:
  pass
