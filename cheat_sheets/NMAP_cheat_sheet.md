# NMAP Cheat Sheet

Base nmap Syntax:

```
nmap [ScanType] [Options] {targets}
```
If no port range is specified, Nmap scans the 1,000 most popular ports.

```
-F Scan 100 most popular ports
-p <port1>-<port2> Port range
-p <port1>,<port2>,... Port List
-pU:53,U:110,T20-445 Mix TCP and UDP
-r Scan linearly (do not randomize ports)
--top-ports <n> Scan n most popular ports
-p-65535 Leaving off initial port in range makes Nmap scan start at port 1
-p0- Leaving off end port in range makes Nmap scan through p
```

## Nmap Scripting Engine

The full list of Nmap Scripting Engine scripts: http://nmap.org/nsedoc/

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
