# Simple Scapy Packet Capture
Here is a Python script that uses the Scapy library to capture a packet:

```
from scapy.all import *

# Define a callback function
def packet_callback(packet):
    print(packet.show())

# Use the sniff() function to capture packets
sniff(prn=packet_callback, filter="tcp", count=1)
```

This script uses the `sniff()` function from Scapy to capture packets. The `prn` argument is set to a callback function, `packet_callback`, which is called for each packet captured. The filter argument is set to "tcp" to capture only TCP packets, and the count argument is set to 1 to stop capturing after the first packet is captured. The `show()` function is used to display the packet information.

You can also use `filter` to capture specific IP or port.

```
sniff(prn=packet_callback, filter="tcp and host 10.1.1.2 and port 80", count=1)
```
It's important to note that capturing packets may require root/admin permissions.

## Saving to a pcap file

Here is a modified version of the script that saves the captured packets to a pcap file:

```
from scapy.all import *

# Define a callback function
def packet_callback(packet):
    print(packet.show())
    wrpcap("captured_packets.pcap", packet, append=True)

# Use the sniff() function to capture packets
sniff(prn=packet_callback, filter="tcp", count=1)

```

This script uses the `wrpcap()` function from Scapy to save the captured packets to a `pcap` file named "captured_packets.pcap". The `append=True` argument is used to append the packets to the file instead of overwriting it.

## Reading pcap files and manipulating the packets

Here is a Python script that uses the Scapy library to read a pcap file and import it:

```
from scapy.all import *

# read the pcap file
packets = rdpcap("captured_packets.pcap")

# iterate through the packets
for packet in packets:
    print(packet.show())
    
```
This script uses the `rdpcap()` function from Scapy to read the pcap file named "captured_packets.pcap" and store it in the packets variable. The packets are then iterated through using a for loop, and the `show()` function is used to display the packet information.

You can also use `ls()` function to list out the layers of the packet.

```
for packet in packets:
    print(packet.ls())
```
It's also possible to filter the packets based on specific layer or field.

```
# filter packets based on destination IP
filtered_packets = [p for p in packets if p.haslayer(IP) and p[IP].dst == "10.1.1.2"]
```

It's important to note that this script assumes that the pcap file is in the same directory as the script, and the file name is "captured_packets.pcap".
