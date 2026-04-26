# Wireshark Display Filters Cheat Sheet

Wireshark is the world's most popular network protocol analyzer. Display filters allow you to focus on specific traffic during analysis.

## 📋 Table of Contents
- [Wireshark Display Filters Cheat Sheet](#wireshark-display-filters-cheat-sheet)
  - [📋 Table of Contents](#-table-of-contents)
  - [Basic Syntax](#basic-syntax)
  - [Comparison Operators](#comparison-operators)
  - [Logical Operators](#logical-operators)
  - [Protocol Filters](#protocol-filters)
  - [IP Filters](#ip-filters)
  - [TCP Filters](#tcp-filters)
  - [UDP Filters](#udp-filters)
  - [HTTP Filters](#http-filters)
  - [DNS Filters](#dns-filters)
  - [TLS/SSL Filters](#tlsssl-filters)
  - [Common Use Cases](#common-use-cases)
    - [Finding Specific Communications](#finding-specific-communications)
    - [Network Issues](#network-issues)
    - [Security Analysis](#security-analysis)
    - [Application Analysis](#application-analysis)
    - [Data Exfiltration Detection](#data-exfiltration-detection)
    - [Performance Analysis](#performance-analysis)
  - [Advanced Filters](#advanced-filters)
  - [Display Filter Macros](#display-filter-macros)
  - [Tips and Tricks](#tips-and-tricks)
  - [Common Filter Combinations](#common-filter-combinations)
  - [Resources](#resources)
  - [Legal Notice](#legal-notice)

## Basic Syntax

```
protocol.field operator value
```

Examples:
```
ip.addr == 192.168.1.1
tcp.port == 80
http.request.method == "GET"
```

## Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equal | `ip.addr == 192.168.1.1` |
| `!=` | Not equal | `tcp.port != 80` |
| `>` | Greater than | `frame.len > 1000` |
| `<` | Less than | `frame.len < 64` |
| `>=` | Greater than or equal | `tcp.window_size >= 65535` |
| `<=` | Less than or equal | `ip.ttl <= 64` |
| `contains` | Contains string | `http.host contains "example"` |
| `matches` | Regex match | `http.host matches ".*\.com$"` |

## Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `and` or `&&` | Logical AND | `ip.addr == 192.168.1.1 and tcp.port == 80` |
| `or` or `\|\|` | Logical OR | `tcp.port == 80 or tcp.port == 443` |
| `not` or `!` | Logical NOT | `not arp` |
| `()` | Grouping | `(tcp.port == 80 or tcp.port == 443) and ip.addr == 192.168.1.1` |

## Protocol Filters

```
# Basic protocols
tcp                     # TCP traffic
udp                     # UDP traffic
icmp                    # ICMP traffic
arp                     # ARP traffic
dns                     # DNS traffic
http                    # HTTP traffic
https                   # HTTPS traffic (TLS on port 443)
tls                     # TLS/SSL traffic
ssh                     # SSH traffic
ftp                     # FTP traffic
smtp                    # SMTP traffic
smb                     # SMB traffic
rdp                     # RDP traffic

# Exclude protocols
!arp                    # Everything except ARP
not tcp                 # Everything except TCP
```

## IP Filters

```
# IP addresses
ip.addr == 192.168.1.1          # Source or destination
ip.src == 192.168.1.1           # Source IP
ip.dst == 192.168.1.1           # Destination IP

# Multiple IPs
ip.addr == 192.168.1.1 or ip.addr == 192.168.1.2

# IP range
ip.addr >= 192.168.1.1 and ip.addr <= 192.168.1.255

# Subnet
ip.addr == 192.168.1.0/24

# Private IP addresses
ip.src_host == 10.0.0.0/8 or ip.src_host == 172.16.0.0/12 or ip.src_host == 192.168.0.0/16

# Broadcast
eth.dst == ff:ff:ff:ff:ff:ff

# TTL
ip.ttl < 10                     # Low TTL (possible traceroute)
ip.ttl == 64                    # Linux default
ip.ttl == 128                   # Windows default

# Fragmented packets
ip.flags.mf == 1                # More fragments
ip.frag_offset > 0              # Fragment offset

# IP version
ip.version == 4                 # IPv4
ipv6                            # IPv6
```

## TCP Filters

```
# TCP ports
tcp.port == 80                  # Source or destination port
tcp.srcport == 80               # Source port
tcp.dstport == 80               # Destination port

# Port ranges
tcp.port >= 1 and tcp.port <= 1024      # Well-known ports
tcp.port > 1024                          # Non-privileged ports

# TCP flags
tcp.flags.syn == 1              # SYN flag
tcp.flags.ack == 1              # ACK flag
tcp.flags.fin == 1              # FIN flag
tcp.flags.reset == 1            # RST flag
tcp.flags.push == 1             # PSH flag
tcp.flags.urg == 1              # URG flag

# TCP flag combinations
tcp.flags.syn == 1 and tcp.flags.ack == 0       # SYN (connection initiation)
tcp.flags.syn == 1 and tcp.flags.ack == 1       # SYN-ACK
tcp.flags.reset == 1                            # Connection reset
tcp.flags == 0x012                              # SYN-ACK (hex)
tcp.flags == 0x002                              # SYN only

# TCP stream analysis
tcp.stream eq 0                 # First TCP stream
tcp.stream eq 5                 # Specific stream number

# TCP analysis flags
tcp.analysis.retransmission     # Retransmitted packets
tcp.analysis.duplicate_ack      # Duplicate ACKs
tcp.analysis.lost_segment       # Lost segments
tcp.analysis.fast_retransmission
tcp.analysis.zero_window        # Zero window
tcp.analysis.window_full

# Window size
tcp.window_size < 1000          # Small window
tcp.window_size == 0            # Zero window

# Sequence numbers
tcp.seq == 0                    # Initial sequence
tcp.ack == 1                    # ACK number

# TCP options
tcp.options.mss_val             # Maximum segment size
tcp.options.wscale              # Window scale
```

## UDP Filters

```
# UDP ports
udp.port == 53                  # DNS
udp.port == 67 or udp.port == 68        # DHCP
udp.port == 161                 # SNMP
udp.port == 123                 # NTP

# UDP length
udp.length > 1000               # Large UDP packets

# UDP checksum
udp.checksum_bad                # Bad checksum
```

## HTTP Filters

```
# HTTP methods
http.request.method == "GET"
http.request.method == "POST"
http.request.method == "PUT"
http.request.method == "DELETE"
http.request.method == "HEAD"

# HTTP status codes
http.response.code == 200       # OK
http.response.code == 301       # Moved Permanently
http.response.code == 302       # Found
http.response.code == 400       # Bad Request
http.response.code == 401       # Unauthorized
http.response.code == 403       # Forbidden
http.response.code == 404       # Not Found
http.response.code == 500       # Internal Server Error
http.response.code >= 400       # All errors

# HTTP host
http.host == "www.example.com"
http.host contains "example"

# HTTP URI
http.request.uri contains "/admin"
http.request.uri matches ".*\\.php$"

# HTTP User-Agent
http.user_agent contains "Mozilla"
http.user_agent contains "curl"
http.user_agent contains "bot"

# HTTP headers
http.cookie                     # Packets with cookies
http.set_cookie                 # Set-Cookie headers
http.authorization              # Authorization headers
http.referer contains "example"

# HTTP content
http.content_type contains "text/html"
http.content_type contains "application/json"
http.content_type contains "image"

# HTTP requests/responses
http.request                    # All HTTP requests
http.response                   # All HTTP responses

# HTTP file transfers
http.request.uri contains ".exe"
http.request.uri contains ".zip"
http.request.uri contains ".pdf"
```

## DNS Filters

```
# DNS queries
dns.flags.response == 0         # DNS queries
dns.flags.response == 1         # DNS responses

# DNS query types
dns.qry.type == 1               # A record (IPv4)
dns.qry.type == 28              # AAAA record (IPv6)
dns.qry.type == 5               # CNAME
dns.qry.type == 15              # MX record
dns.qry.type == 16              # TXT record
dns.qry.type == 2               # NS record
dns.qry.type == 6               # SOA record
dns.qry.type == 12              # PTR record
dns.qry.type == 255             # ANY record

# DNS query name
dns.qry.name contains "example.com"
dns.qry.name matches ".*\\.ru$"

# DNS response codes
dns.flags.rcode == 0            # No error
dns.flags.rcode == 3            # Name error (NXDOMAIN)

# DNS over TCP (unusual, possible zone transfer)
dns and tcp

# Large DNS responses
dns and frame.len > 512
```

## TLS/SSL Filters

```
# TLS handshake
tls.handshake.type == 1         # Client Hello
tls.handshake.type == 2         # Server Hello
tls.handshake.type == 11        # Certificate
tls.handshake.type == 12        # Server Key Exchange
tls.handshake.type == 14        # Server Hello Done

# TLS versions
tls.record.version == 0x0301    # TLS 1.0
tls.record.version == 0x0302    # TLS 1.1
tls.record.version == 0x0303    # TLS 1.2
tls.record.version == 0x0304    # TLS 1.3

# SSL/TLS alerts
tls.alert_message

# Server Name Indication (SNI)
tls.handshake.extensions_server_name contains "example.com"

# Certificate information
tls.handshake.certificate

# Cipher suites
tls.handshake.ciphersuite
```

## Common Use Cases

### Finding Specific Communications

```
# Conversation between two hosts
ip.addr == 192.168.1.1 and ip.addr == 192.168.1.2

# Web traffic from specific host
ip.src == 192.168.1.100 and (tcp.port == 80 or tcp.port == 443)

# All traffic except to/from specific IP
!(ip.addr == 192.168.1.1)

# Traffic to external networks (not private)
!(ip.dst_host == 10.0.0.0/8 or ip.dst_host == 172.16.0.0/12 or ip.dst_host == 192.168.0.0/16)
```

### Network Issues

```
# TCP retransmissions
tcp.analysis.retransmission

# Duplicate ACKs (possible packet loss)
tcp.analysis.duplicate_ack

# TCP zero windows (receiver buffer full)
tcp.analysis.zero_window

# Out of order packets
tcp.analysis.out_of_order

# Large packets (potential issues)
frame.len > 1500

# Small packets (potential efficiency issues)
frame.len < 60

# ICMP destination unreachable
icmp.type == 3

# High latency indicators
tcp.time_delta > 1
```

### Security Analysis

```
# Port scanning indicators
tcp.flags.syn == 1 and tcp.flags.ack == 0       # SYN scan
tcp.flags == 0                                   # NULL scan
tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1  # XMAS scan

# Failed connection attempts
tcp.flags.reset == 1

# Suspicious user agents
http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "nmap"

# SQL injection attempts
http.request.uri contains "union" or http.request.uri contains "select" or http.request.uri contains "'"

# XSS attempts
http.request.uri contains "<script>"

# Directory traversal
http.request.uri contains "../"

# Command injection
http.request.uri contains ";" or http.request.uri contains "|" or http.request.uri contains "&"

# Password in clear text (insecure protocols)
ftp or telnet or http.authorization

# ARP spoofing detection
arp.duplicate-address-detected

# DHCP starvation
dhcp.option.dhcp == 3                   # DHCP requests

# SMB/CIFS suspicious activity
smb.cmd == 0x2d                         # Session Setup
smb.path contains "IPC$"
```

### Application Analysis

```
# Web application specific
http.request.uri contains "/login"
http.request.uri contains "/admin"
http.cookie contains "session"

# Database traffic
tcp.port == 3306                        # MySQL
tcp.port == 5432                        # PostgreSQL
tcp.port == 1433                        # MS SQL
tcp.port == 1521                        # Oracle

# Email protocols
tcp.port == 25                          # SMTP
tcp.port == 110                         # POP3
tcp.port == 143                         # IMAP
tcp.port == 587                         # SMTP submission
tcp.port == 993                         # IMAPS
tcp.port == 995                         # POP3S

# File sharing
tcp.port == 445                         # SMB
tcp.port == 139                         # NetBIOS
tcp.port == 2049                        # NFS

# Remote access
tcp.port == 22                          # SSH
tcp.port == 23                          # Telnet
tcp.port == 3389                        # RDP
tcp.port == 5900                        # VNC
```

### Data Exfiltration Detection

```
# Large outbound transfers
ip.dst_host != 192.168.0.0/16 and frame.len > 1400

# Unusual protocols
!(tcp or udp or icmp or arp)

# DNS tunneling indicators
dns and frame.len > 512

# ICMP tunneling
icmp and frame.len > 100

# Outbound connections to non-standard ports
tcp.dstport > 10000
```

### Performance Analysis

```
# Time-based filters
frame.time_relative > 10                # After 10 seconds
frame.time_delta > 0.1                  # 100ms between packets

# Bandwidth hogs
frame.len > 1400 and tcp.port == 80

# Slow responses
http.time > 1                           # HTTP response time > 1 sec

# TCP handshake issues
tcp.flags.syn == 1 and tcp.analysis.ack_rtt > 0.5
```

## Advanced Filters

```
# Beacon-like traffic (C2 detection)
tcp.flags.push == 1 and tcp.len < 100

# IPv6 tunneling
ipv6.nxt == 41                          # IPv6 in IPv6

# VLAN tagged traffic
vlan.id == 100

# MPLS labeled traffic
mpls

# Multicast traffic
ip.dst == 224.0.0.0/4

# Broadcast traffic
eth.dst == ff:ff:ff:ff:ff:ff

# Malformed packets
malformed

# Expert info (warnings/notes)
expert.severity == warning
expert.severity == note
expert.severity == error
```

## Display Filter Macros

You can create custom macros in Wireshark for frequently used filters:

```
# Go to: Edit > Preferences > Filter Expressions > Add

# Example macros:
${ip:private}    = (ip.addr >= 10.0.0.0 and ip.addr <= 10.255.255.255) or ...
${port:web}      = tcp.port == 80 or tcp.port == 443 or tcp.port == 8080
${port:mail}     = tcp.port == 25 or tcp.port == 110 or tcp.port == 143
```

## Tips and Tricks

1. **Right-click any field** in packet details to quickly create filters
2. **Use autocomplete** - Start typing and press Ctrl+Space
3. **Save frequently used filters** as filter buttons
4. **Color code traffic** - View > Coloring Rules
5. **Follow streams** - Right-click packet > Follow > TCP/HTTP Stream
6. **Use capture filters** (BPF syntax) to reduce captured data
7. **Export filtered packets** - File > Export Specified Packets

## Common Filter Combinations

```
# Web browsing from specific IP
ip.src == 192.168.1.100 and (http or tls)

# Email traffic
tcp.port == 25 or tcp.port == 110 or tcp.port == 143 or tcp.port == 587

# Windows file sharing
tcp.port == 445 or tcp.port == 139 or udp.port == 137 or udp.port == 138

# All encrypted traffic
tls or ssh or tcp.port == 993 or tcp.port == 995

# Network reconnaissance
(tcp.flags.syn == 1 and tcp.flags.ack == 0) or arp or icmp

# Application layer only
tcp.len > 0 or udp.length > 8
```

## Resources

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Wiki](https://wiki.wireshark.org/)

## Legal Notice

⚠️ **WARNING**: Only analyze network traffic you have explicit permission to capture and examine. Unauthorized network monitoring may be illegal.

---

**Pro Tip**: Combine display filters with Wireshark's statistics features (Statistics menu) for powerful traffic analysis.

