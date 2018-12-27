# NMAP Cheat Sheet

Base nmap Syntax:

```
nmap [ScanType] [Options] {targets}
```
If no port range is specified, Nmap scans the 1,000 most popular ports.

- `-p <port1>-<port2>`: Scans a port range
- `-p <port1>,<port2>,...`: Scans a port list
- `-pU:53,U:110,T20-445`: Mix TCP and UDP
- `-r`: Scans linearly (does not randomize ports)
- `--top-ports <n>`: Scan n most popular ports
- `-p-65535`: Leaving off the initial port in range makes Nmap scan start at port 1
- `-p0-`: Leaving off the end port in range makes Nmap scan through p

## Port Status

- Open: This indicates that an application is listening for connections on this port.
- Closed: This indicates that the probes were received but there is no application listening on this port.
- Filtered: This indicates that the probes were not received and the state could not be established. It also indicates that the probes are being dropped by some kind of filtering.
- Unfiltered: This indicates that the probes were received but a state could not be established.
- Open/Filtered: This indicates that the port was filtered or open but Nmap couldn’t establish the state.
- Closed/Filtered: This indicates that the port was filtered or closed but Nmap couldn’t establish the state.

## Scan Types

- `-sn`: Probe only (host discovery, not port scan)
- `-sS`: SYN Scan
- `-sT`: TCP Connect Scan
- `-sU`: UDP Scan
- `-sV`: Version Scan
- `-O`: Used for OS Detection/fingerprinting
- `--scanflags`: Sets custom list of TCP using `URG ACK PSH RST SYN FIN` in any order

## Probing Options

- `-Pn`: Don't probe (assume all hosts are up)
- `-PB`: Default probe (TCP 80, 445 & ICMP)
- `-PS<portlist>` : Checks if ssytems are online by probing TCP ports
- `-PE`: Using ICMP Echo Request
- `-PP`: Using ICMP Timestamp Request
- `-PM`: Using ICMP Netmask Request

## Timing Options
`-T0` (Paranoid): Very slow, used for IDS evasion
`-T1` (Sneaky): Quite slow, used for IDS evasion
`-T2` (Polite): Slows down to consume less bandwidth, runs ~10 times slower than default
`-T3` (Normal): Default, a dynamic timing model based on target responsiveness
`-T4` (Aggressive): Assumes a fast and reliable network and may overwhelm targets
`-T5` (Insane): Very aggressive; will likely overwhelm targets or miss open ports

## Fine-Grained Timing Options

- `--min-hostgroup/max-hostgroup <size> `: Parallel host scan group sizes
- `--min-parallelism/max-parallelism <numprobes>`: Probes parallelization
- `--min-rtt-timeout/max-rtttimeout/initial-rtt-timeout <time>`: Specifies probe round trip time.
- `--max-retries <tries>`: Caps number of port scan probe retransmissions.
- `--host-timeout <time>`: Gives up on target after this long
- `--scan-delay/--max-scan-delay <time>`: Adjusts delay between probes
- `--min-rate <number>`: Send packets no slower than `<number>` per second
- `--max-rate <number>`: Send packets no faster than `<number>` per second

## Nmap Scripting Engine

The full list of Nmap Scripting Engine scripts: http://nmap.org/nsedoc/

`nmap -sC` runs default scripts...

Running individual or groups of scripts:
`nmap --script=<ScriptName>| <ScriptCategory>|<ScriptDir>`
  
Using the list of script arguments:
`nmap --script-args=<Name1=Value1,...>`

Updating the script database:
`nmap --script-updatedb`


Some particularly useful scripts include:

- dns-zone-transfer: Attempts to pull a zone file (AXFR) from a DNS server.
```
$ nmap --script dns-zonetransfer.nse --script-args dns-zonetransfer.domain=<domain> -p53 <hosts>
```

- http-robots.txt: Harvests robots.txt files from discovered web servers.
```
$ nmap --script http-robots.txt <hosts>
```

- smb-brute: Attempts to determine valid username and password combinations via automated guessing.
```
$ nmap --script smb-brute.nse -p445 <hosts>
```

- smb-psexec: Attempts to run a series of programs on the target machine, using credentials provided as scriptargs.
```
$ nmap --script smb-psexec.nse –script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 <hosts>
```

### Nmap Scripting Engine Categories
The most common Nmap scripting engine categories:
- auth: Utilize credentials or bypass authentication on target hosts.
- broadcast: Discover hosts not included on command line by broadcasting on local network.
- brute: Attempt to guess passwords on target systems, for a variety of protocols, including http, SNMP, IAX, MySQL, VNC, etc.
- default: Scripts run automatically when -sC or -A are used.
- discovery: Try to learn more information about target hosts through public sources of information, SNMP, directory services, and more.
- dos: May cause denial of service conditions in target hosts.
- exploit: Attempt to exploit target systems.
- external: Interact with third-party systems not included in target list.
- fuzzer: Send unexpected input in network protocol fields.
- intrusive: May crash target, consume excessive resources, or otherwise impact target machines in a malicious fashion.
- malware: Look for signs of malware infection on the target hosts.
- safe: Designed not to impact target in a negative fashion.
- version: Measure the version of software or protocols on the target hosts.
- vul: Measure whether target systems have a known vulnerability.

## Output Options

- `-oN`: Standard Nmap output
- `-oG`: Greppable format
- `-oX`: XML format
- `-oA`: <basename> Generate Nmap, Greppable, and XML output files using basename for files
  
 ## Additional Options
 
- `-n`: Disables reverse IP address lookups
- `-6`: Uses IPv6 only
- `-A`: Uses several features, including OS Detection, Version Detection, Script Scanning (default), and traceroute
- `--reason`: Displays the reason Nmap thinks that the port is open, closed, or filtered
