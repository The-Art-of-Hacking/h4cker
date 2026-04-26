# Tcpdump Cheat Sheet

Tcpdump is a powerful command-line packet analyzer tool used for network troubleshooting and security analysis. It captures and displays packets being transmitted or received over a network.

## 📋 Table of Contents
- [Basic Syntax](#basic-syntax)
- [Interface Selection](#interface-selection)
- [Basic Captures](#basic-captures)
- [Filtering Traffic](#filtering-traffic)
- [Protocol Filters](#protocol-filters)
- [Port Filters](#port-filters)
- [Host Filters](#host-filters)
- [Advanced Filters](#advanced-filters)
- [Output Options](#output-options)
- [Reading Captures](#reading-captures)
- [Practical Examples](#practical-examples)

## Basic Syntax

```bash
tcpdump [options] [filter expression]
```

Common options:
- `-i`: Interface to capture from
- `-n`: Don't resolve hostnames
- `-nn`: Don't resolve hostnames or port names
- `-v`: Verbose output
- `-vv`: More verbose
- `-vvv`: Even more verbose
- `-c`: Capture n packets
- `-w`: Write to file
- `-r`: Read from file
- `-s`: Snapshot length (0 for full packet)
- `-A`: Print packet in ASCII
- `-X`: Print packet in hex and ASCII

## Interface Selection

```bash
# List available interfaces
tcpdump -D

# Capture on specific interface
tcpdump -i eth0

# Capture on all interfaces
tcpdump -i any

# Capture on wireless interface
tcpdump -i wlan0

# Capture on loopback
tcpdump -i lo
```

## Basic Captures

```bash
# Capture packets (default 65535 bytes)
tcpdump

# Capture n packets then stop
tcpdump -c 10

# Capture full packets (no truncation)
tcpdump -s 0

# Capture with timestamps
tcpdump -tttt

# Capture without hostname resolution
tcpdump -n

# Capture without hostname and port resolution
tcpdump -nn

# Verbose output
tcpdump -v

# Very verbose output
tcpdump -vv

# Extremely verbose output
tcpdump -vvv
```

## Filtering Traffic

### By Host

```bash
# Capture traffic from specific host
tcpdump host 192.168.1.1

# Capture traffic from source host
tcpdump src host 192.168.1.1

# Capture traffic to destination host
tcpdump dst host 192.168.1.1

# Capture traffic between two hosts
tcpdump host 192.168.1.1 and host 192.168.1.2
```

### By Network

```bash
# Capture traffic from network
tcpdump net 192.168.1.0/24

# Capture traffic from source network
tcpdump src net 192.168.1.0/24

# Capture traffic to destination network
tcpdump dst net 192.168.1.0/24
```

### By Port

```bash
# Capture traffic on specific port
tcpdump port 80

# Capture traffic on source port
tcpdump src port 80

# Capture traffic on destination port
tcpdump dst port 80

# Capture traffic on port range
tcpdump portrange 21-23

# Capture traffic NOT on specific port
tcpdump not port 22
```

## Protocol Filters

```bash
# TCP traffic
tcpdump tcp

# UDP traffic
tcpdump udp

# ICMP traffic
tcpdump icmp

# ARP traffic
tcpdump arp

# IPv6 traffic
tcpdump ip6

# Specific protocol by number
tcpdump proto 6  # TCP
tcpdump proto 17 # UDP
```

## Port Filters

```bash
# HTTP traffic
tcpdump port 80

# HTTPS traffic
tcpdump port 443

# SSH traffic
tcpdump port 22

# DNS traffic
tcpdump port 53

# FTP traffic
tcpdump port 21

# SMTP traffic
tcpdump port 25

# MySQL traffic
tcpdump port 3306

# Multiple ports
tcpdump port 80 or port 443

# Port range
tcpdump portrange 6000-6010
```

## Host Filters

```bash
# Single host
tcpdump host 192.168.1.1

# Multiple hosts (OR)
tcpdump host 192.168.1.1 or host 192.168.1.2

# Exclude host
tcpdump not host 192.168.1.1

# Source host
tcpdump src host 192.168.1.1

# Destination host
tcpdump dst host 192.168.1.1
```

## Advanced Filters

### Logical Operators

```bash
# AND operator
tcpdump tcp and port 80

# OR operator
tcpdump tcp or udp

# NOT operator
tcpdump not icmp

# Complex expressions
tcpdump 'tcp and (port 80 or port 443)'

# NOT with multiple conditions
tcpdump 'not (host 192.168.1.1 and port 22)'
```

### TCP Flags

```bash
# SYN packets
tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# SYN-ACK packets
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# RST packets
tcpdump 'tcp[tcpflags] & tcp-rst != 0'

# FIN packets
tcpdump 'tcp[tcpflags] & tcp-fin != 0'

# PSH-ACK packets
tcpdump 'tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)'

# URG packets
tcpdump 'tcp[tcpflags] & tcp-urg != 0'
```

### Packet Size

```bash
# Packets less than 128 bytes
tcpdump less 128

# Packets greater than 1024 bytes
tcpdump greater 1024

# Packets exactly 512 bytes
tcpdump 'len == 512'

# Packets between sizes
tcpdump 'len > 100 and len < 200'
```

### Broadcast and Multicast

```bash
# Broadcast packets
tcpdump broadcast

# Multicast packets
tcpdump multicast

# Neither broadcast nor multicast
tcpdump not broadcast and not multicast
```

## Output Options

### Display Formats

```bash
# ASCII output
tcpdump -A

# Hex output
tcpdump -X

# Hex and ASCII output
tcpdump -XX

# Only packet headers
tcpdump -q

# Link-level headers
tcpdump -e
```

### Save to File

```bash
# Write to pcap file
tcpdump -w capture.pcap

# Write with packet count
tcpdump -c 1000 -w capture.pcap

# Write full packets
tcpdump -s 0 -w capture.pcap

# Write with rotation (size-based)
tcpdump -w capture.pcap -C 100  # 100MB per file

# Write with rotation (time-based)
tcpdump -w capture.pcap -G 3600  # New file every hour

# Write with ring buffer
tcpdump -w capture.pcap -W 5  # Keep only 5 files
```

### Timestamps

```bash
# Default timestamp
tcpdump -tttt

# Unix timestamp
tcpdump -tt

# Microseconds since first packet
tcpdump -ttt

# Difference between packets
tcpdump -tttt
```

## Reading Captures

```bash
# Read from pcap file
tcpdump -r capture.pcap

# Read and filter
tcpdump -r capture.pcap port 80

# Read with verbose output
tcpdump -r capture.pcap -vv

# Read and display specific packets
tcpdump -r capture.pcap -c 10

# Read and save filtered traffic
tcpdump -r input.pcap port 443 -w output.pcap
```

## Practical Examples

### HTTP Traffic Analysis

```bash
# Capture HTTP GET requests
tcpdump -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Capture HTTP POST requests
tcpdump -A -s 0 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'

# Capture HTTP traffic with GET/POST
tcpdump -A -s 0 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'

# Simple HTTP capture
tcpdump -A -s 0 port 80

# HTTP hosts
tcpdump -A -s 0 'tcp port 80' | grep -i 'host:'

# HTTP User-Agents
tcpdump -A -s 0 'tcp port 80' | grep -i 'user-agent:'
```

### DNS Traffic Analysis

```bash
# All DNS traffic
tcpdump -i any port 53

# DNS queries
tcpdump -i any 'udp port 53'

# DNS responses
tcpdump -i any 'tcp port 53 or udp port 53'

# Specific domain queries
tcpdump -i any port 53 | grep 'example.com'

# DNS over TCP (zone transfers)
tcpdump -i any tcp port 53
```

### HTTPS/SSL Traffic

```bash
# HTTPS traffic
tcpdump port 443

# TLS handshake
tcpdump -A 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'

# SSL certificate exchange
tcpdump -A -s 0 'tcp port 443 and tcp[32:4] = 0x16030100'
```

### Email Traffic

```bash
# SMTP traffic
tcpdump -A port 25

# SMTP to specific server
tcpdump -A 'port 25 and dst host mail.example.com'

# POP3 traffic
tcpdump -A port 110

# IMAP traffic
tcpdump -A port 143

# Secure email (SMTPS, POP3S, IMAPS)
tcpdump port 465 or port 995 or port 993
```

### FTP Traffic

```bash
# FTP control connection
tcpdump port 21

# FTP data connection
tcpdump port 20

# Both FTP ports
tcpdump port 21 or port 20

# FTP commands
tcpdump -A port 21 | grep 'USER\|PASS\|STOR\|RETR'
```

### SSH Traffic

```bash
# SSH connections
tcpdump port 22

# New SSH connections (SYN packets)
tcpdump 'tcp port 22 and tcp[tcpflags] & tcp-syn != 0'

# SSH to specific host
tcpdump 'port 22 and dst host 192.168.1.1'
```

### Network Scanning Detection

```bash
# SYN scans
tcpdump 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# NULL scans
tcpdump 'tcp[tcpflags] == 0'

# XMAS scans
tcpdump 'tcp[tcpflags] & (tcp-fin|tcp-urg|tcp-push) == (tcp-fin|tcp-urg|tcp-push)'

# Port scan from specific host
tcpdump 'tcp[tcpflags] & tcp-syn != 0 and src host 192.168.1.1'
```

### ARP Monitoring

```bash
# All ARP traffic
tcpdump arp

# ARP requests
tcpdump 'arp[6:2] == 1'

# ARP replies
tcpdump 'arp[6:2] == 2'

# ARP for specific IP
tcpdump 'arp and host 192.168.1.1'

# Gratuitous ARP
tcpdump 'arp and src host 192.168.1.1 and dst host 192.168.1.1'
```

### ICMP Analysis

```bash
# All ICMP traffic
tcpdump icmp

# Ping requests (echo request)
tcpdump 'icmp[icmptype] == 8'

# Ping replies (echo reply)
tcpdump 'icmp[icmptype] == 0'

# ICMP destination unreachable
tcpdump 'icmp[icmptype] == 3'

# ICMP redirect
tcpdump 'icmp[icmptype] == 5'

# ICMP time exceeded
tcpdump 'icmp[icmptype] == 11'
```

### IPv6 Traffic

```bash
# All IPv6 traffic
tcpdump ip6

# IPv6 TCP traffic
tcpdump 'ip6 and tcp'

# IPv6 ICMPv6
tcpdump 'ip6 and icmp6'

# IPv6 specific host
tcpdump 'ip6 host 2001:db8::1'
```

### VLAN Traffic

```bash
# VLAN tagged traffic
tcpdump 'vlan'

# Specific VLAN
tcpdump 'vlan 100'

# Multiple VLANs
tcpdump 'vlan 100 or vlan 200'

# Traffic on VLAN and port
tcpdump 'vlan and port 80'
```

## Capturing Specific Attacks

### SQL Injection Attempts

```bash
# Common SQL injection patterns
tcpdump -A -s 0 port 80 | grep -i 'select\|union\|insert\|update\|delete\|drop'

# OR-based injection
tcpdump -A -s 0 port 80 | grep -i "' or '1'='1"
```

### XSS Attempts

```bash
# Common XSS patterns
tcpdump -A -s 0 port 80 | grep -i '<script>'
```

### Suspicious User Agents

```bash
# Detect suspicious tools
tcpdump -A port 80 | grep -i 'user-agent:' | grep -i 'nikto\|sqlmap\|nmap\|masscan'
```

## Performance Optimization

```bash
# Reduce output verbosity
tcpdump -q

# Don't resolve names (faster)
tcpdump -nn

# Limit snapshot length
tcpdump -s 96  # Capture only headers

# Use BPF filtering (faster than grep)
tcpdump 'tcp port 80' # Better than: tcpdump | grep ':80'

# Buffered output
tcpdump -l | tee capture.log

# Direct to /dev/null for live counting
tcpdump -c 1000 > /dev/null
```

## Useful Combinations

```bash
# Web traffic (HTTP and HTTPS)
tcpdump 'tcp port 80 or tcp port 443'

# All traffic except SSH
tcpdump 'not port 22'

# Incoming SYN packets (potential connection attempts)
tcpdump 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst host $(hostname -I | cut -d" " -f1)'

# Traffic from specific subnet to web servers
tcpdump 'src net 192.168.1.0/24 and (dst port 80 or dst port 443)'

# Non-standard ports (possibly malicious)
tcpdump 'tcp[0:2] > 1024 and tcp[0:2] < 65535'

# Large packets (possible exfiltration)
tcpdump 'greater 1500'

# Capture first 100 packets of HTTP traffic
tcpdump -c 100 -w http_sample.pcap port 80
```

## Integration with Other Tools

```bash
# Pipe to Wireshark
tcpdump -i eth0 -U -w - | wireshark -k -i -

# Pipe to tshark
tcpdump -i eth0 -U -w - | tshark -r -

# Count packets by type
tcpdump -n -r capture.pcap | awk '{print $3}' | sort | uniq -c | sort -nr

# Extract HTTP hosts
tcpdump -A -s 0 -r capture.pcap port 80 | grep 'Host:' | sort | uniq

# Real-time monitoring dashboard
watch -n 1 'tcpdump -i eth0 -c 100 2>&1 | tail -20'
```

## Troubleshooting Common Issues

```bash
# Permission denied - run with sudo
sudo tcpdump

# Interface not found - list interfaces first
tcpdump -D

# Buffer full - increase buffer size
tcpdump -B 4096

# Packets dropped - reduce packet capture
tcpdump -s 128  # Only capture headers

# Check statistics
tcpdump -i eth0 -c 1000 -q
# Shows packets captured/dropped at end
```

## Resources

- [Tcpdump Official Documentation](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Tcpdump Examples](https://danielmiessler.com/study/tcpdump/)
- [BPF Syntax Reference](https://biot.com/capstats/bpf.html)


