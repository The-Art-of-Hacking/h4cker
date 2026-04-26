## SMB NETBIOS Enumeration Tips

### Tool Tips

#### Enum4Linux
```
enum4linux x.x.x.x
```

#### Nmap
```
nmap -v -p 139,445 -oG smb.txt 192.168.88.0-254
```

#### nbtscan
```
nbtscan -r 192.168.11.0/24
```

#### nmblookup
```
nmblookup -A target
```
#### smbclient
```
smbclient //192.168.31.147/karen -I 192.168.88.251
```
#### rpcclient
```
rpcclient -U "" 192.168.88.251 // connect as blank user /nobody
```
#### smbmap
```
smbmap -u "" -p "" -d MYGROUP -H 192.168.88.251
```

## Metasploit 

### SMB version
```
msf auxiliary(scanner/smb/smb_version) > use auxiliary/scanner/smb/smb_version
msf auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.88.251
RHOSTS => 192.168.31.142
msf auxiliary(scanner/smb/smb_version) > run
[*] 192.168.31.142:139    - Host could not be identified: Unix (Samba 2.2.1a)
```
### SMB brute force
```
use auxiliary/scanner/smb/smb_login
```

### Existing users
```
msf auxiliary(scanner/smb/smb_lookupsid) > use auxiliary/scanner/smb/smb_lookupsid
msf auxiliary(scanner/smb/smb_lookupsid) > set RHOSTS 192.168.31.142
RHOSTS => 192.168.31.142
msf auxiliary(scanner/smb/smb_lookupsid) > run
[*] 192.168.31.142:139    - PIPE(LSARPC) LOCAL(MYGROUP - 5-21-4157223341-3243572438-1405127623) DOMAIN(MYGROUP - )
[*] 192.168.31.142:139    - TYPE=0 NAME=Administrator rid=500

```
### upload a file
smbclient //192.168.31.142/ADMIN$ -U "nobody"%"somepassword" -c "put 40280.py"


## NMAP SMB scripts ==
nmap --script smb-* --script-args=unsafe=1 192.168.10.55 

```
┌─[omar@websploit]─[~]
└──╼ $  ls -lh /usr/share/nmap/scripts/smb*	
smb-brute.nse
smb-enum-domains.nse
smb-enum-groups.nse
smb-enum-processes.nse
smb-enum-sessions.nse
smb-enum-shares.nse
smb-enum-users.nse
smb-flood.nse
smb-ls.nse
smb-mbenum.nse
smb-os-discovery.nse
smb-print-text.nse
smb-psexec.nse
smb-security-mode.nse
smb-server-stats.nse
smb-system-info.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-regsvc-dos.nse
smbv2-enabled.nse
```

### mount SMB shares in Linux
```
smbclient -L \\WIN7\ -I 192.168.13.218
smbclient -L \\WIN7\ADMIN$  -I 192.168.13.218
smbclient -L \\WIN7\C$ -I 192.168.13.218
smbclient -L \\WIN7\IPC$ -I 192.168.13.218
smbclient \\192.168.13.236\some-share -o user=root,pass=root,workgroup=BOB
```

### mount SMB share to a afolder
```
mount -t auto --source //192.168.31.147/kathy --target /tmp/smb/ -o username=root,workgroup=WORKGROUP
```

### mount SMB shares in Windows (via cmd)
```
net use X: \\<server>\<sharename> /USER:<domain>\<username> <password> /PERSISTENT:YES
```
