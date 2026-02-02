# Windows Rootkit Detection and System Compromise Guide

This guide provides comprehensive commands, techniques, and strategies for identifying rootkits and system compromise on Windows systems. It covers both manual detection methods and automated tools for forensic analysis and incident response.

## 📋 Table of Contents
- [Understanding Rootkits](#understanding-rootkits)
- [Types of Rootkits](#types-of-rootkits)
- [Detection Strategies](#detection-strategies)
- [Windows Native Commands](#windows-native-commands)
- [System Integrity Verification](#system-integrity-verification)
- [Memory Analysis](#memory-analysis)
- [Network Activity Monitoring](#network-activity-monitoring)
- [Registry Analysis](#registry-analysis)
- [File System Analysis](#file-system-analysis)
- [Process and Service Analysis](#process-and-service-analysis)
- [Behavioral Indicators](#behavioral-indicators)
- [Advanced Detection Tools](#advanced-detection-tools)
- [Incident Response Workflow](#incident-response-workflow)

## Understanding Rootkits

Rootkits are sophisticated malware designed to hide their presence and maintain persistent, privileged access to a compromised system. They operate by:
- Hiding processes, files, registry keys, and network connections
- Intercepting and manipulating system calls
- Maintaining persistence through various techniques
- Evading detection by security software

## Types of Rootkits

### 1. User-Mode Rootkits
- Operate at application level
- Hook user-mode APIs (e.g., Windows API functions)
- Easier to detect than kernel-mode rootkits
- Examples: Hooking Process32First/Next, registry enumeration APIs

### 2. Kernel-Mode Rootkits
- Operate at the kernel level with highest privileges
- Hook system service dispatch table (SSDT)
- Modify kernel objects and data structures
- More difficult to detect and remove
- Examples: DKOM (Direct Kernel Object Manipulation)

### 3. Bootkits
- Infect the Master Boot Record (MBR) or boot sector
- Load before the operating system
- Extremely difficult to detect
- Persist through OS reinstallation
- Examples: TDL4, Olmasco

### 4. Firmware/UEFI Rootkits
- Infect system firmware or UEFI
- Survive OS reinstallation and disk replacement
- Require specialized tools for detection
- Examples: LoJax, MosaicRegressor

## Detection Strategies

### Multi-Layered Detection Approach
1. **Baseline Comparison** - Compare current state against known good baseline
2. **Signature-Based Detection** - Use known malware signatures
3. **Behavioral Analysis** - Monitor for suspicious activities
4. **Heuristic Analysis** - Identify anomalies and deviations
5. **Cross-View Comparison** - Compare different API views of system state
6. **Memory Forensics** - Analyze volatile memory for artifacts

### Detection Principles
- **Trust but Verify** - Don't rely solely on OS-provided APIs
- **Multiple Perspectives** - Use different methods to enumerate system objects
- **Known Good Baseline** - Maintain clean system snapshots for comparison
- **Live vs. Dead Analysis** - Combine runtime and offline analysis
- **Defense in Depth** - Layer multiple detection techniques

## Windows Native Commands

### System Information Gathering

```cmd
:: Get detailed system information
systeminfo

:: Check Windows version and build
ver
wmic os get Caption,Version,BuildNumber,OSArchitecture

:: List installed hotfixes and patches
wmic qfe list full
systeminfo | findstr /B /C:"Hotfix"

:: Check system uptime (recent reboot may indicate compromise cleanup)
systeminfo | findstr /B /C:"System Boot Time"
net statistics workstation

:: Check for Safe Mode (rootkits may disable Safe Mode)
bcdedit /enum
```

### Process Analysis

```cmd
:: List all running processes
tasklist /v
tasklist /svc
wmic process list full

:: Find processes by name
tasklist /fi "imagename eq svchost.exe"

:: List processes with full path
wmic process get ProcessId,ParentProcessId,CommandLine,ExecutablePath

:: Check process owners
tasklist /v /fo list

:: Identify unsigned or suspicious executables
wmic process where "ExecutablePath is not null" get ExecutablePath,ProcessId
wmic process get ExecutablePath,ProcessId | findstr /v /i "C:\Windows"

:: Check process creation time
wmic process get ProcessId,Name,CreationDate

:: List process modules/DLLs
tasklist /m
tasklist /m /fi "pid eq 1234"

:: PowerShell process enumeration
powershell "Get-Process | Select-Object Name,Id,Path,Company,ProductVersion | Sort-Object Name"
powershell "Get-Process | Where-Object {$_.Path -notlike 'C:\Windows\*'} | Select-Object Name,Id,Path"
```

### Service Analysis

```cmd
:: List all services
sc query
sc query type= all state= all
wmic service list full

:: List running services
net start
sc query state= all | findstr "RUNNING"

:: Get service details
sc qc ServiceName
sc queryex ServiceName

:: Check service binary path (look for unusual paths or DLLs)
wmic service get Name,DisplayName,PathName,StartMode,State

:: Find services running from unusual locations
wmic service where "PathName not like '%C:\Windows%'" get Name,PathName,State

:: Check service DLL (for svchost)
sc qc ServiceName

:: List services and their process IDs
tasklist /svc

:: PowerShell service enumeration
powershell "Get-Service | Select-Object Name,Status,StartType,DisplayName"
powershell "Get-WmiObject Win32_Service | Select-Object Name,PathName,StartMode,State | Where-Object {$_.PathName -notlike '*C:\Windows\*'}"
```

### Driver Analysis

```cmd
:: List loaded drivers
driverquery /v
driverquery /si

:: List drivers with path
driverquery /v /fo list

:: Get driver details
wmic sysdriver list full

:: Find unsigned drivers (potential rootkit indicator)
wmic sysdriver get Name,DisplayName,State,Status,PathName

:: PowerShell driver enumeration
powershell "Get-WindowsDriver -Online | Select-Object Driver,ProviderName,Date,Version"
powershell "driverquery /v | Select-String -Pattern 'Running'"
```

### Startup Programs

```cmd
:: List startup programs (Registry Run keys)
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

:: List all startup locations
wmic startup list full

:: Check Startup folder
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"

:: Scheduled tasks
schtasks /query /fo LIST /v
schtasks /query /fo TABLE

:: PowerShell startup enumeration
powershell "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User"
```

### Network Connections

```cmd
:: List all active connections
netstat -ano
netstat -anob

:: List listening ports
netstat -an | findstr LISTENING

:: Show process associated with each connection
netstat -ano | findstr ESTABLISHED

:: List routing table
route print

:: Display ARP cache (check for ARP poisoning)
arp -a

:: DNS cache (may reveal C2 domains)
ipconfig /displaydns

:: Active SMB sessions
net session
net use

:: PowerShell network connections
powershell "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
powershell "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}"
```

### File System Analysis

```cmd
:: Find hidden files
dir /a:h /s C:\
attrib C:\ /s

:: Find alternate data streams (ADS)
dir /r C:\
powershell "Get-Item C:\* -Stream * | Where-Object {$_.Stream -ne ':$DATA'}"

:: Search for recently modified files
forfiles /P C:\ /S /D -7 /C "cmd /c echo @path @fdate"

:: Find files by date
wmic datafile where "LastModified>'20240101000000.000000+000'" get Name,LastModified

:: Check file integrity (compare hashes)
certutil -hashfile C:\path\to\file.exe SHA256

:: PowerShell file search
powershell "Get-ChildItem C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime"
powershell "Get-ChildItem C:\Windows\System32 -Filter *.exe | Get-FileHash -Algorithm SHA256 | Format-Table"
```

## System Integrity Verification

### File Signature Verification

```cmd
:: Verify digital signatures
sigverif

:: Check individual file signature
powershell "Get-AuthenticodeSignature C:\path\to\file.exe | Select-Object Status,SignerCertificate"

:: Find unsigned executables in System32
powershell "Get-ChildItem C:\Windows\System32\*.exe | Get-AuthenticodeSignature | Where-Object {$_.Status -ne 'Valid'}"

:: Verify all system files
powershell "Get-ChildItem C:\Windows\System32 -Include *.exe,*.dll,*.sys -Recurse | Get-AuthenticodeSignature | Where-Object {$_.Status -ne 'Valid'} | Select-Object Path,Status"
```

### System File Checker

```cmd
:: Scan and repair system files
sfc /scannow

:: Scan but don't repair
sfc /verifyonly

:: Scan specific file
sfc /scanfile=C:\Windows\System32\kernel32.dll

:: View SFC scan results
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log
```

### DISM (Deployment Image Servicing and Management)

```cmd
:: Check system health
DISM /Online /Cleanup-Image /CheckHealth

:: Scan system health
DISM /Online /Cleanup-Image /ScanHealth

:: Restore system health
DISM /Online /Cleanup-Image /RestoreHealth
```

### Windows Resource Protection

```cmd
:: Check for protected file modifications
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log > "%userprofile%\Desktop\sfcdetails.txt"
```

## Memory Analysis

### Live Memory Acquisition

```cmd
:: Create memory dump (requires admin)
wmic process where name="lsass.exe" get ProcessId
tasklist | findstr lsass

:: Using Windows Task Manager
:: Right-click process > Create Dump File

:: PowerShell memory dump
powershell "Get-Process | Select-Object Name,Id,WS,PM,VM | Sort-Object WS -Descending"

:: Detect process injection
powershell "Get-Process | Where-Object {$_.Modules.FileName -like '*dll*'} | Select-Object Name,Modules"
```

### Memory Analysis Commands

```cmd
:: List loaded DLLs for a process
tasklist /m /fi "pid eq 1234"

:: Check for injected DLLs
powershell "Get-Process -Id 1234 | Select-Object -ExpandProperty Modules | Where-Object {$_.FileName -notlike 'C:\Windows\*'}"

:: Detect hollowed processes (command line vs. image path mismatch)
wmic process get ProcessId,ParentProcessId,CommandLine,ExecutablePath

:: Check process memory (unusual memory usage)
wmic process get ProcessId,Name,WorkingSetSize,VirtualSize

:: PowerShell process memory analysis
powershell "Get-Process | Select-Object Name,Id,@{n='Memory(MB)';e={[math]::Round($_.WS/1MB,2)}} | Sort-Object 'Memory(MB)' -Descending"
```

## Network Activity Monitoring

### Active Connections Monitoring

```cmd
:: Monitor connections in real-time
netstat -ano 5

:: Find connections to specific IP
netstat -ano | findstr 192.168.1.1

:: List listening ports and associated programs
netstat -anob | findstr LISTENING

:: PowerShell network monitoring
powershell "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Format-Table"
```

### DNS and Network Configuration

```cmd
:: Check DNS settings (potential DNS hijacking)
ipconfig /all

:: Display DNS cache
ipconfig /displaydns

:: Check hosts file (common rootkit modification)
type C:\Windows\System32\drivers\etc\hosts

:: Check for proxy settings
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer

:: PowerShell DNS and network config
powershell "Get-DnsClientServerAddress"
powershell "Get-NetAdapter | Get-DnsClientServerAddress"
```

### Firewall Configuration

```cmd
:: Check firewall status
netsh advfirewall show allprofiles

:: List firewall rules
netsh advfirewall firewall show rule name=all

:: PowerShell firewall rules
powershell "Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object Name,Direction,Action"
powershell "Get-NetFirewallRule | Where-Object {$_.Action -eq 'Allow' -and $_.Direction -eq 'Inbound'}"
```

## Registry Analysis

### Common Persistence Locations

```cmd
:: AutoRun keys
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

:: Services
reg query HKLM\System\CurrentControlSet\Services

:: AppInit_DLLs (DLL injection)
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs

:: Winlogon
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

:: Image File Execution Options (IFEO) - debugger hijacking
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

:: Explorer Shell Extensions
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
reg query HKLM\Software\Classes\*\ShellEx\ContextMenuHandlers

:: Browser Helper Objects (BHOs)
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects

:: LSA Providers (credential theft)
reg query HKLM\System\CurrentControlSet\Control\Lsa
reg query HKLM\System\CurrentControlSet\Control\SecurityProviders

:: WMI persistence
wmic /namespace:\\root\subscription path __EventFilter GET __RELPATH
wmic /namespace:\\root\subscription path CommandLineEventConsumer GET __RELPATH
wmic /namespace:\\root\subscription path __FilterToConsumerBinding GET __RELPATH
```

### Registry Export and Analysis

```cmd
:: Export registry hive for analysis
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run run_keys.reg

:: Search registry for suspicious entries
reg query HKLM /s /f "suspicious" 2>nul
reg query HKCU /s /f "suspicious" 2>nul

:: PowerShell registry analysis
powershell "Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'"
powershell "Get-ChildItem -Path 'HKLM:\System\CurrentControlSet\Services' -Recurse | Where-Object {$_.Property -contains 'ImagePath'}"
```

## File System Analysis

### Suspicious File Search

```cmd
:: Find files with no extension
dir C:\ /s /b | findstr /v "\."

:: Find executable files in user directories
dir %USERPROFILE% /s /b *.exe
dir %APPDATA% /s /b *.exe

:: Find recently created files
forfiles /P C:\ /S /D -1 /C "cmd /c echo @path @fdate @ftime"

:: Find files with double extensions
dir /s C:\ | findstr "\..*\."

:: Find files in temp directories
dir %TEMP% /s
dir C:\Windows\Temp /s

:: PowerShell file system analysis
powershell "Get-ChildItem -Path C:\ -Include *.exe,*.dll,*.sys -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}"
powershell "Get-ChildItem -Path C:\Windows\System32 | Where-Object {!$_.PSIsContainer} | Get-FileHash -Algorithm MD5"
```

### Alternate Data Streams (ADS)

```cmd
:: Find files with ADS
dir /r /s C:\

:: PowerShell ADS detection
powershell "Get-Item -Path C:\* -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'}"
powershell "Get-ChildItem -Path C:\ -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } | Where-Object {$_.Stream -ne ':$DATA'}"

:: Read ADS content
more < file.txt:hidden_stream
powershell "Get-Content -Path 'file.txt' -Stream 'hidden_stream'"

:: Remove ADS
powershell "Remove-Item -Path 'file.txt' -Stream 'hidden_stream'"
```

### File Permissions Analysis

```cmd
:: Check file permissions
icacls C:\Windows\System32\cmd.exe

:: Find files with unusual permissions
icacls C:\Windows\System32\*.exe | findstr "Everyone"
icacls C:\Windows\System32\*.exe | findstr "Users"

:: PowerShell ACL analysis
powershell "Get-Acl C:\Windows\System32\cmd.exe | Format-List"
powershell "Get-ChildItem C:\Windows\System32\*.exe | Get-Acl | Where-Object {$_.Access.IdentityReference -like '*Everyone*'}"
```

## Process and Service Analysis

### Advanced Process Analysis

```cmd
:: Process tree view
wmic process get ProcessId,ParentProcessId,CommandLine,ExecutablePath
powershell "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Sort-Object ProcessId"

:: Process with network connections
netstat -ano | findstr ESTABLISHED
powershell "Get-Process -Id (Get-NetTCPConnection -State Established).OwningProcess -ErrorAction SilentlyContinue | Select-Object -Unique Name,Id,Path"

:: Detect process injection techniques
powershell "Get-Process | Get-Member"
powershell "Get-Process | Where-Object {$_.Modules.Count -gt 100} | Select-Object Name,Id,@{Name='ModuleCount';Expression={$_.Modules.Count}}"

:: Check for process masquerading
wmic process where "Name='svchost.exe'" get ProcessId,ParentProcessId,CommandLine,ExecutablePath
powershell "Get-Process svchost | Select-Object Id,Path | Where-Object {$_.Path -notlike '*C:\Windows\System32\*'}"
```

### Service Configuration Analysis

```cmd
:: Find services with unusual ImagePath
sc query state= all | findstr "SERVICE_NAME"
for /F "tokens=2 delims=:" %%a in ('sc query state= all ^| findstr "SERVICE_NAME"') do @sc qc %%a | findstr "BINARY_PATH_NAME"

:: Detect service DLL hijacking
powershell "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -Name ImagePath -ErrorAction SilentlyContinue | Where-Object {$_.ImagePath -notlike '*System32*'}"

:: Check service dependencies
sc enumdepend ServiceName

:: Verify service executable signatures
powershell "Get-WmiObject Win32_Service | Select-Object Name,PathName | ForEach-Object {Get-AuthenticodeSignature $_.PathName.Split('\"')[1]}"
```

### Driver and Kernel Analysis

```cmd
:: List kernel drivers
driverquery /v | findstr /i "kernel"

:: Check driver signing
powershell "Get-WindowsDriver -Online | Select-Object Driver,ProviderName,Version,Date | Where-Object {$_.ProviderName -notlike '*Microsoft*'}"

:: Find suspicious driver paths
driverquery /v | findstr /v "C:\Windows\System32"

:: Check for SSDT hooks (requires specialized tools)
:: Use tools like GMER, Rootkit Detector, etc.
```

## Behavioral Indicators

### Common Rootkit Behaviors

1. **Hidden Processes**
   - Process visible in one tool but not another
   - High CPU usage with no visible process
   - Parent-child process relationships that don't make sense

2. **Hidden Files/Directories**
   - Disk space usage doesn't match file listing
   - Files visible with direct path but not in directory listing
   - Discrepancies between different file enumeration methods

3. **Hidden Network Connections**
   - Unexplained network traffic
   - Connections not shown by netstat
   - Unusual DNS queries or external connections

4. **Hidden Registry Keys**
   - Registry keys that can't be enumerated normally
   - Keys with null bytes or special characters in names

5. **System Instability**
   - Unexpected crashes or freezes
   - Security tools failing or disabled
   - Inability to access certain files or directories

### Detection Techniques

```cmd
:: Compare process listings from multiple sources
tasklist > tasklist.txt
wmic process get ProcessId,Name > wmic.txt
powershell "Get-Process | Select-Object Id,Name" > ps.txt
:: Compare the outputs for discrepancies

:: Check for hidden files by comparing sizes
dir C:\ /s > dir_normal.txt
dir C:\ /s /a:h > dir_hidden.txt
:: Compare file counts and sizes

:: Network connection cross-check
netstat -ano > netstat.txt
powershell "Get-NetTCPConnection" > ps_net.txt
:: Look for connections in one but not the other

:: Registry key comparison
reg query HKLM\Software > reg_normal.txt
:: Use alternate tools (RegDelNull, Process Hacker, etc.)
:: Compare results
```

## Advanced Detection Tools

### Microsoft Sysinternals Suite

```cmd
:: Autoruns - Comprehensive startup program scanner
autorunsc.exe -a * -c -h -s -v > autoruns.csv

:: Process Explorer - Advanced process monitoring
procexp.exe

:: Process Monitor - Real-time file, registry, and process monitoring
procmon.exe

:: TCPView - Network connection monitoring
tcpview.exe

:: RootkitRevealer - Rootkit detection
rootkitrevealer.exe

:: Sigcheck - File signature verification
sigcheck.exe -e -s C:\Windows\System32

:: Streams - ADS detector
streams.exe -s C:\

:: PsService - Service information
psservice.exe

:: PsFile - Show files opened remotely
psfile.exe

:: PsList - Process listing with detail
pslist.exe -t

:: ListDLLs - DLL listing for processes
listdlls.exe -u
```

### Third-Party Detection Tools

```cmd
:: GMER - Rootkit detector
:: Run GMER and perform full scan
gmer.exe

:: Rootkit Detector - Sophos
:: Automated rootkit scanning
RootkitDetector.exe

:: TDSS Killer - Kaspersky
:: Specialized bootkit/rootkit remover
tdsskiller.exe

:: Malwarebytes Anti-Rootkit
:: Dedicated rootkit scanner
mbar.exe

:: Bitdefender Rootkit Remover
:: Automated rootkit removal
RootkitRemover.exe

:: ESET Online Scanner
:: Cloud-based scanning
OnlineScannerApp.exe

:: Chkrootkit (Linux) - for dual-boot systems
:: Mount Windows drive from Linux
chkrootkit -r /mnt/windows
```

### Memory Forensics Tools

```cmd
:: Volatility Framework
:: Requires memory dump acquisition first
volatility.exe -f memdump.raw --profile=Win10x64 pslist
volatility.exe -f memdump.raw --profile=Win10x64 psscan
volatility.exe -f memdump.raw --profile=Win10x64 dlllist
volatility.exe -f memdump.raw --profile=Win10x64 driverscan
volatility.exe -f memdump.raw --profile=Win10x64 ssdt
volatility.exe -f memdump.raw --profile=Win10x64 malfind

:: Rekall - Memory forensics framework
rekall.exe -f memdump.raw pslist
rekall.exe -f memdump.raw dlllist
rekall.exe -f memdump.raw ssdt
```

### YARA Rules for Detection

```cmd
:: Create YARA rule for rootkit signatures
:: Example: rootkit.yar
:: rule RootkitIndicator {
::     strings:
::         $str1 = "rootkit" nocase
::         $str2 = "hidden" nocase
::     condition:
::         any of them
:: }

:: Scan files with YARA
yara64.exe -r rootkit.yar C:\
yara64.exe -r rootkit.yar C:\Windows\System32

:: Scan running processes with YARA
yara64.exe -p rootkit.yar
```

## Incident Response Workflow

### Phase 1: Preparation

```cmd
:: Document baseline system state
systeminfo > baseline_systeminfo.txt
tasklist /v > baseline_tasklist.txt
netstat -ano > baseline_netstat.txt
wmic startup list full > baseline_startup.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > baseline_run.txt

:: Create system restore point
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Pre-Scan", 100, 7
```

### Phase 2: Detection

```cmd
:: Run comprehensive scans
autorunsc.exe -a * -c -h -s -v > scan_autoruns.csv
sigcheck.exe -e -s -v C:\Windows\System32 > scan_sigcheck.txt
powershell "Get-Process | Export-Csv scan_processes.csv"
netstat -ano > scan_netstat.txt

:: Check for anomalies
fc baseline_tasklist.txt scan_tasklist.txt
fc baseline_netstat.txt scan_netstat.txt
```

### Phase 3: Analysis

```cmd
:: Analyze findings
:: Review scan results
:: Compare against baseline
:: Investigate suspicious processes/files/registry keys

:: Export suspicious artifacts
reg export HKLM\System\CurrentControlSet\Services\SuspiciousService service_export.reg
wmic process where "name='suspicious.exe'" get ProcessId,CommandLine,ExecutablePath
```

### Phase 4: Containment

```cmd
:: Isolate system (if needed)
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

:: Stop suspicious processes
taskkill /F /PID <pid>
taskkill /F /IM suspicious.exe

:: Stop suspicious services
sc stop SuspiciousService
net stop SuspiciousService

:: Disable suspicious startup entries
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SuspiciousEntry /f
schtasks /delete /tn "SuspiciousTask" /f
```

### Phase 5: Eradication

```cmd
:: Remove rootkit files
del /F /Q C:\path\to\rootkit.exe
powershell "Remove-Item -Path 'C:\path\to\rootkit.exe' -Force"

:: Remove registry persistence
reg delete HKLM\System\CurrentControlSet\Services\RootkitService /f

:: Remove scheduled tasks
schtasks /delete /tn "RootkitTask" /f

:: Scan and remove with anti-malware
:: Use specialized rootkit removal tools (TDSS Killer, Malwarebytes Anti-Rootkit, etc.)

:: Remove drivers (if applicable)
sc delete RootkitDriver
pnputil /delete-driver oem##.inf /uninstall /force
```

### Phase 6: Recovery

```cmd
:: Verify system integrity
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

:: Update system
wuauclt /detectnow /updatenow
powershell "Install-WindowsUpdate -AcceptAll"

:: Reset security settings
netsh advfirewall reset
netsh advfirewall set allprofiles state on

:: Update antivirus signatures
powershell "Update-MpSignature"

:: Restore from clean backup (if severe compromise)
:: Use Windows System Restore or full system restore
```

### Phase 7: Post-Incident

```cmd
:: Document findings
:: Create incident report with:
::   - Timeline of events
::   - Indicators of compromise (IOCs)
::   - Actions taken
::   - Lessons learned

:: Update detection rules
:: Add IOCs to security tools
:: Update monitoring rules

:: Strengthen security posture
:: Apply security patches
:: Update security policies
:: Implement additional monitoring
```

## Best Practices

### Prevention
1. **Keep Systems Updated** - Apply security patches promptly
2. **Use Security Software** - Deploy and maintain antivirus/EDR
3. **Implement Least Privilege** - Limit administrative access
4. **Enable Secure Boot** - Prevent bootkit installation
5. **Monitor System Changes** - Use file integrity monitoring
6. **Network Segmentation** - Limit lateral movement
7. **Application Whitelisting** - Control executable execution

### Detection
1. **Regular Scanning** - Perform periodic rootkit scans
2. **Baseline Comparison** - Maintain and compare against known good state
3. **Multiple Tools** - Don't rely on single detection method
4. **Memory Analysis** - Include memory forensics in investigation
5. **Cross-Validation** - Verify findings with multiple techniques
6. **Log Analysis** - Review system and security logs regularly

### Response
1. **Documented Procedures** - Follow established IR playbook
2. **Evidence Preservation** - Maintain chain of custody
3. **Thorough Investigation** - Don't stop at first indicator
4. **Complete Removal** - Ensure all components are removed
5. **Root Cause Analysis** - Determine initial infection vector
6. **Lessons Learned** - Update procedures based on findings

## Indicators of Compromise (IOCs)

### Common IOCs
- Unexpected network connections to external IPs
- Processes running from unusual locations (temp, appdata)
- Modified system files or services
- Unsigned or suspicious drivers
- Registry modifications in persistence locations
- Hidden files or alternate data streams
- Unusual parent-child process relationships
- Security tool failures or unexpected behavior
- High CPU/memory usage with no visible cause
- Unexplained disk activity
- Modified hosts file or DNS settings
- Suspicious scheduled tasks or WMI subscriptions

### Investigation Checklist
- [ ] Document system state and create forensic image
- [ ] Compare current state against baseline
- [ ] Check all persistence mechanisms
- [ ] Verify digital signatures of system files
- [ ] Review process list and network connections
- [ ] Analyze loaded drivers and kernel modules
- [ ] Check for hidden files and ADS
- [ ] Review registry for suspicious entries
- [ ] Analyze memory dump for rootkit artifacts
- [ ] Check event logs for anomalies
- [ ] Verify system file integrity
- [ ] Review user accounts and privileges
- [ ] Check for backdoor accounts or scheduled tasks
- [ ] Analyze network traffic for C2 communications
- [ ] Document all findings and IOCs

## Additional Resources

### Tools
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/)
- [GMER Rootkit Detector](http://www.gmer.net/)
- [Volatility Framework](https://www.volatilityfoundation.org/)
- [Rekall Memory Forensics](http://www.rekall-forensic.com/)
- [YARA](https://virustotal.github.io/yara/)
- [Malwarebytes Anti-Rootkit](https://www.malwarebytes.com/)
- [Kaspersky TDSSKiller](https://www.kaspersky.com/downloads/tdsskiller)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [RegDelNull](https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull)

### Documentation
- [Microsoft Security Response Center](https://www.microsoft.com/en-us/msrc)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Digital Forensics](https://www.sans.org/digital-forensics-incident-response/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Books and Papers
- "Rootkits and Bootkits" by Alex Matrosov, Eugene Rodionov, Sergey Bratus
- "The Rootkit Arsenal" by Bill Blunden
- "Windows Internals" by Mark Russinovich, David Solomon, Alex Ionescu
- "Malware Analyst's Cookbook" by Michael Ligh et al.
- "Practical Malware Analysis" by Michael Sikorski, Andrew Honig

### Training
- [SANS FOR500: Windows Forensic Analysis](https://www.sans.org/cyber-security-courses/windows-forensic-analysis/)
- [SANS FOR508: Advanced Incident Response](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [GIAC Reverse Engineering Malware (GREM)](https://www.giac.org/certification/reverse-engineering-malware-grem)

---

**Note:** This guide is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before performing security assessments.
