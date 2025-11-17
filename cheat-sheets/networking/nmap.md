# NMAP Cheat Sheet

Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It's essential for penetration testing, network inventory, and security assessments.

## 📋 Table of Contents
- [Basic Syntax](#basic-syntax)
- [Target Specification](#target-specification)
- [Port Specification](#port-specification)
- [Port Status](#port-status)
- [Scan Types](#scan-types)
- [Host Discovery](#host-discovery)
- [Timing Options](#timing-options)
- [Evasion Techniques](#evasion-techniques)
- [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
- [Output Options](#output-options)
- [Practical Examples](#practical-examples)

## Basic Syntax

```bash
nmap [ScanType] [Options] {targets}
```

If no port range is specified, Nmap scans the 1,000 most popular ports.

## Target Specification

```bash
# Single IP
nmap 192.168.1.1

# IP range
nmap 192.168.1.1-254

# Subnet
nmap 192.168.1.0/24

# Multiple targets
nmap 192.168.1.1 192.168.1.2 192.168.1.3

# From file
nmap -iL targets.txt

# Exclude targets
nmap 192.168.1.0/24 --exclude 192.168.1.1

# Exclude from file
nmap 192.168.1.0/24 --excludefile exclude.txt
```

## Port Specification

| Option | Description | Example |
|--------|-------------|---------|
| `-p <port>` | Scan specific port | `nmap -p 22 192.168.1.1` |
| `-p <port1>-<port2>` | Scan port range | `nmap -p 1-100 192.168.1.1` |
| `-p <port1>,<port2>,...` | Scan port list | `nmap -p 22,80,443 192.168.1.1` |
| `-p-` | Scan all 65535 ports | `nmap -p- 192.168.1.1` |
| `-p U:53,T:21-25,80` | Mix TCP and UDP | `nmap -pU:53,T:21-25,80 192.168.1.1` |
| `-F` | Fast scan (100 ports) | `nmap -F 192.168.1.1` |
| `--top-ports <n>` | Scan n most popular ports | `nmap --top-ports 20 192.168.1.1` |
| `-r` | Scan ports linearly | `nmap -r 192.168.1.1` |

## Port Status

| Status | Description |
|--------|-------------|
| **Open** | Application is listening for connections on this port |
| **Closed** | Probes were received but no application is listening |
| **Filtered** | Probes were not received (firewall/filtering detected) |
| **Unfiltered** | Probes were received but state could not be established |
| **Open\|Filtered** | Port was filtered or open but Nmap couldn't determine which |
| **Closed\|Filtered** | Port was filtered or closed but Nmap couldn't determine which |

## Scan Types

| Option | Scan Type | Description | Requires Root |
|--------|-----------|-------------|---------------|
| `-sS` | SYN Scan | Stealthy, doesn't complete TCP handshake | Yes |
| `-sT` | TCP Connect | Completes full TCP handshake | No |
| `-sU` | UDP Scan | Scans UDP ports (slow) | Yes |
| `-sA` | ACK Scan | Maps firewall rulesets | Yes |
| `-sW` | Window Scan | Detects open ports via TCP Window | Yes |
| `-sM` | Maimon Scan | FIN/ACK probe | Yes |
| `-sN` | NULL Scan | No flags set (stealth) | Yes |
| `-sF` | FIN Scan | Only FIN flag set | Yes |
| `-sX` | Xmas Scan | FIN, PSH, and URG flags | Yes |
| `-sV` | Version Detection | Determines service/version info | No |
| `-sn` | Ping Scan | Host discovery only, no port scan | No |
| `-sI` | Idle Scan | Uses zombie host | Yes |
| `-sO` | IP Protocol Scan | Determines IP protocols | Yes |
| `--scanflags` | Custom Scan | Custom TCP flags | Yes |

### Scan Type Examples

```bash
# SYN Scan (stealthy)
sudo nmap -sS 192.168.1.1

# TCP Connect (no root required)
nmap -sT 192.168.1.1

# UDP Scan
sudo nmap -sU 192.168.1.1

# Version Detection
nmap -sV 192.168.1.1

# OS Detection
sudo nmap -O 192.168.1.1

# Aggressive scan (OS, version, scripts, traceroute)
sudo nmap -A 192.168.1.1

# Custom TCP flags
sudo nmap --scanflags URGACKPSHRSTSYNFIN 192.168.1.1
```

## Host Discovery

| Option | Description |
|--------|-------------|
| `-sn` | Ping scan only (no port scan) |
| `-Pn` | Skip host discovery (assume all hosts are up) |
| `-PS <portlist>` | TCP SYN discovery on specified ports |
| `-PA <portlist>` | TCP ACK discovery on specified ports |
| `-PU <portlist>` | UDP discovery on specified ports |
| `-PE` | ICMP Echo Request discovery |
| `-PP` | ICMP Timestamp Request discovery |
| `-PM` | ICMP Netmask Request discovery |
| `-PO <protocols>` | IP Protocol ping |
| `-PR` | ARP ping (local network) |
| `--traceroute` | Trace path to host |

### Discovery Examples

```bash
# Ping scan to find live hosts
nmap -sn 192.168.1.0/24

# Assume all hosts are up (skip ping)
nmap -Pn 192.168.1.0/24

# TCP SYN ping on ports 22, 80, 443
sudo nmap -PS22,80,443 192.168.1.0/24

# ICMP Echo Request
nmap -PE 192.168.1.0/24

# ARP ping (local network only)
sudo nmap -PR 192.168.1.0/24
```

## Timing Options

Nmap has built-in timing templates and fine-grained controls.

### Timing Templates

| Option | Name | Description | Use Case |
|--------|------|-------------|----------|
| `-T0` | Paranoid | Extremely slow (5min between probes) | IDS evasion |
| `-T1` | Sneaky | Very slow (15sec between probes) | IDS evasion |
| `-T2` | Polite | Slow (0.4sec between probes) | Low bandwidth |
| `-T3` | Normal | Default timing | Standard scan |
| `-T4` | Aggressive | Fast (assumes good network) | Fast networks |
| `-T5` | Insane | Very fast (may miss ports) | Very fast networks |

### Fine-Grained Timing

```bash
# Parallel host scan group sizes
nmap --min-hostgroup 50 --max-hostgroup 100 192.168.1.0/24

# Probe parallelization
nmap --min-parallelism 10 --max-parallelism 100 192.168.1.1

# RTT timeout
nmap --initial-rtt-timeout 100ms --max-rtt-timeout 300ms 192.168.1.1

# Max retries
nmap --max-retries 2 192.168.1.1

# Host timeout
nmap --host-timeout 5m 192.168.1.1

# Scan delay
nmap --scan-delay 1s 192.168.1.1

# Rate limiting
nmap --min-rate 100 --max-rate 1000 192.168.1.1
```

## Evasion Techniques

### Fragmentation

```bash
# Fragment packets
nmap -f 192.168.1.1

# Set custom MTU (must be multiple of 8)
nmap --mtu 16 192.168.1.1
```

### Decoy Scanning

```bash
# Use decoy IPs
nmap -D RND:10 192.168.1.1

# Specify decoy IPs
nmap -D decoy1,decoy2,ME,decoy3 192.168.1.1

# Random source port
nmap --source-port 53 192.168.1.1
nmap -g 53 192.168.1.1
```

### Spoofing

```bash
# Spoof MAC address
nmap --spoof-mac 0 192.168.1.1
nmap --spoof-mac Apple 192.168.1.1
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Spoof source IP
nmap -S 192.168.1.100 192.168.1.1

# Use specific interface
nmap -e eth0 192.168.1.1
```

### Bad Checksum

```bash
# Send packets with bad TCP/UDP checksums
nmap --badsum 192.168.1.1
```

## Nmap Scripting Engine (NSE)

NSE extends Nmap's capabilities with scripts for advanced detection, vulnerability scanning, and exploitation.

### Script Categories

| Category | Description |
|----------|-------------|
| `auth` | Authentication credential discovery |
| `broadcast` | Broadcast discovery |
| `brute` | Brute force attacks |
| `default` | Default scripts (run with `-sC`) |
| `discovery` | Advanced host/service discovery |
| `dos` | Denial of service detection |
| `exploit` | Exploit vulnerabilities |
| `external` | External service queries |
| `fuzzer` | Protocol fuzzing |
| `intrusive` | May crash services |
| `malware` | Malware detection |
| `safe` | Non-intrusive scripts |
| `version` | Version detection enhancement |
| `vuln` | Vulnerability detection |

### NSE Usage

```bash
# Run default scripts
nmap -sC 192.168.1.1

# Run specific script
nmap --script=http-title 192.168.1.1

# Run multiple scripts
nmap --script=http-title,http-headers 192.168.1.1

# Run script category
nmap --script=vuln 192.168.1.1

# Run all scripts except
nmap --script "not intrusive" 192.168.1.1

# Script with arguments
nmap --script=http-wordpress-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1

# Update script database
nmap --script-updatedb

# Get script help
nmap --script-help=http-title
```

### Popular NSE Scripts

```bash
# DNS zone transfer
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p53 ns1.example.com

# HTTP robots.txt
nmap --script http-robots.txt 192.168.1.1

# HTTP title
nmap --script http-title 192.168.1.1

# SSL certificate info
nmap --script ssl-cert -p443 192.168.1.1

# SMB vulnerabilities
nmap --script smb-vuln-* -p445 192.168.1.1

# SMB brute force
nmap --script smb-brute -p445 192.168.1.1

# SSH brute force
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt -p22 192.168.1.1

# FTP anonymous login
nmap --script ftp-anon -p21 192.168.1.1

# MySQL info
nmap --script mysql-info -p3306 192.168.1.1

# Heartbleed vulnerability
nmap --script ssl-heartbleed -p443 192.168.1.1

# Shellshock vulnerability
nmap --script http-shellshock --script-args uri=/cgi-bin/test.sh 192.168.1.1

# Vulnerability scan
nmap --script vuln 192.168.1.1
```

## Output Options

| Option | Format | Description |
|--------|--------|-------------|
| `-oN <file>` | Normal | Standard Nmap output |
| `-oX <file>` | XML | XML format (for parsing) |
| `-oG <file>` | Grepable | Easy to grep |
| `-oS <file>` | ScRipT KIdd|3 | Script kiddie format |
| `-oA <basename>` | All | Output in all formats |
| `-v` | Verbose | Increase verbosity |
| `-vv` | Very Verbose | Even more verbosity |
| `-d` | Debug | Debugging output |
| `--reason` | Reason | Show reason for port state |
| `--open` | Open Ports | Only show open ports |
| `--packet-trace` | Packet Trace | Show packets sent/received |

### Output Examples

```bash
# Normal output
nmap -oN scan_results.txt 192.168.1.1

# XML output
nmap -oX scan_results.xml 192.168.1.1

# All formats
nmap -oA scan_results 192.168.1.1

# Show only open ports
nmap --open 192.168.1.1

# Verbose with reason
nmap -v --reason 192.168.1.1

# Packet trace
nmap --packet-trace 192.168.1.1
```

## Additional Options

```bash
# Disable reverse DNS lookup (faster)
nmap -n 192.168.1.1

# Enable reverse DNS for all hosts
nmap -R 192.168.1.1

# Use specific DNS servers
nmap --dns-servers 8.8.8.8,8.8.4.4 192.168.1.1

# IPv6 scanning
nmap -6 fe80::1

# Treat all hosts as online (skip ping)
nmap -Pn 192.168.1.1

# Max hostgroup size
nmap --max-hostgroup 100 192.168.1.0/24

# Resume scan from output file
nmap --resume scan_results.txt
```

## Practical Examples

### Basic Network Reconnaissance

```bash
# Quick scan of common ports
nmap -F 192.168.1.0/24

# Full port scan with service detection
nmap -p- -sV 192.168.1.1

# Aggressive scan (OS, version, scripts, traceroute)
sudo nmap -A 192.168.1.1

# Scan for web servers
nmap -p80,443 --open 192.168.1.0/24
```

### Stealth Scanning

```bash
# SYN scan with decoys
sudo nmap -sS -D RND:10 192.168.1.1

# Fragmented packets
sudo nmap -f -sS 192.168.1.1

# Very slow scan for IDS evasion
sudo nmap -sS -T1 192.168.1.1

# Random data length
sudo nmap --data-length 25 192.168.1.1
```

### Vulnerability Assessment

```bash
# Scan for common vulnerabilities
nmap --script vuln 192.168.1.1

# Scan for specific vulnerabilities
nmap --script "smb-vuln-*" -p445 192.168.1.0/24

# Web server vulnerability scan
nmap --script "http-vuln-*" -p80,443 192.168.1.1

# Database vulnerability scan
nmap --script "mysql-vuln-*" -p3306 192.168.1.1
```

### Service Enumeration

```bash
# Enumerate SMB shares
nmap --script smb-enum-shares -p445 192.168.1.1

# Enumerate users
nmap --script smb-enum-users -p445 192.168.1.1

# Enumerate DNS records
nmap --script dns-brute example.com

# HTTP enumeration
nmap --script http-enum -p80,443 192.168.1.1
```

### Complete Network Audit

```bash
# Comprehensive network audit
sudo nmap -sS -sV -O -p- --script "default and safe" -oA audit_results 192.168.1.0/24

# Fast initial scan
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Detailed scan of live hosts
sudo nmap -sS -sV -O -A -iL live_hosts.txt -oA detailed_scan
```

## Performance Tips

1. **Use appropriate timing**: `-T4` for most networks, `-T5` for very fast networks
2. **Skip reverse DNS**: Use `-n` to speed up scans
3. **Scan specific ports**: Avoid `-p-` unless necessary
4. **Use parallelism**: Adjust `--max-parallelism` for better performance
5. **Skip ping**: Use `-Pn` if hosts don't respond to ping
6. **Use multiple instances**: Split large IP ranges across multiple Nmap processes

## Common Scan Combinations

```bash
# Quick network sweep
nmap -sn 192.168.1.0/24

# Standard port scan
nmap -sS -T4 192.168.1.1

# Comprehensive scan
sudo nmap -sS -sV -O -A -p- 192.168.1.1

# Stealth scan
sudo nmap -sS -T1 -f -D RND:5 --randomize-hosts 192.168.1.0/24

# Web server scan
nmap -p80,443 --script "http-*" 192.168.1.0/24

# Windows scan
nmap -p135,139,445 --script "smb-*" 192.168.1.0/24

# Database scan
nmap -p1433,3306,5432 --script "*-info" 192.168.1.0/24
```

## Resources

- [Official Nmap Website](https://nmap.org/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NSE Script Documentation](https://nmap.org/nsedoc/)
- [Nmap Network Scanning Book](https://nmap.org/book/)

## Legal Notice

⚠️ **WARNING**: Only scan networks and systems you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.
