#!/usr/bin/python
# Author: Omar Santos @santosomar
# version 1.0
# This is a quick demonstration on how to use the python nmap library
#   * Pre-requisite: nmap python library.
#   * Install it with pip install python-nmap
#####################################################################

import sys
try:
    import nmap
except:
    sys.exit("[!] It looks like the nmap library is not installed in your system. You can install it with: pip install python-nmap")

# The arguments to be processed
if len(sys.argv) != 3:
    sys.exit("Please provide two arguments the first being the targets the second the ports")
addr = str(sys.argv[1])
port = str(sys.argv[2])

# the scanner part

my_scanner = nmap.PortScanner()
my_scanner.scan(addr, port)
for host in my_scanner.all_hosts():
    if not my_scanner[host].hostname():
        print("Not able to find the hostname for IP address %s") % (host)
    else:
        print("The hostname for IP address %s is %s") % (host, my_scanner[host].hostname())

#this prints the results of the scan in a csv file.
print(my_scanner.csv())
