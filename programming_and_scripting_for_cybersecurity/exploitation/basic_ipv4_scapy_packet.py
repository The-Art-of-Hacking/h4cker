from scapy.all import *

# create the packet
packet = IP(src="10.1.1.2", dst="10.3.2.88")/TCP(dport=445)

# send the packet
send(packet)

# You can also use sr() function for sending and receiving packet at the same time.
# ans, unans = sr(packet, timeout=2)
