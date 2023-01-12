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

