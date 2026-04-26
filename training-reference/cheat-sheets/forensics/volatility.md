# Volatility Memory Forensics Cheat Sheet

Volatility is an open-source memory forensics framework for incident response and malware analysis. It extracts digital artifacts from volatile memory (RAM) dumps.

## 📋 Table of Contents
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Image Identification](#image-identification)
- [Process Analysis](#process-analysis)
- [Network Analysis](#network-analysis)
- [Registry Analysis](#registry-analysis)
- [Malware Detection](#malware-detection)
- [File Extraction](#file-extraction)
- [Timeline Analysis](#timeline-analysis)
- [Advanced Analysis](#advanced-analysis)

## Installation

```bash
# Volatility 2.x
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install

# Volatility 3 (recommended)
pip3 install volatility3

# Or with git
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
```

## Basic Usage

### Volatility 2

```bash
# Basic syntax
python vol.py -f <memory_dump> --profile=<profile> <plugin>

# Get help
python vol.py -h
python vol.py <plugin> -h

# List available plugins
python vol.py --info
```

### Volatility 3

```bash
# Basic syntax
python3 vol.py -f <memory_dump> <plugin>

# Get help
python3 vol.py -h

# List available plugins
python3 vol.py --help
```

## Image Identification

### Identify OS Profile (Volatility 2)

```bash
# Identify the OS profile
python vol.py -f memory.dmp imageinfo

# Alternative method
python vol.py -f memory.dmp kdbgscan

# For Windows 10
python vol.py -f memory.dmp --profile=Win10x64_19041 <plugin>

# Common profiles:
# Win7SP1x86, Win7SP1x64
# Win10x64_14393, Win10x64_15063, Win10x64_17134, Win10x64_18362
# WinXPSP2x86, WinXPSP3x86
# VistaSP0x86, VistaSP0x64
```

### Volatility 3 (Auto-detects)

```bash
# Volatility 3 auto-detects the OS
python3 vol.py -f memory.dmp windows.info

# For Linux dumps
python3 vol.py -f memory.dmp linux.info
```

## Process Analysis

### List Processes

```bash
# Volatility 2
python vol.py -f memory.dmp --profile=Win7SP1x64 pslist
python vol.py -f memory.dmp --profile=Win7SP1x64 pstree
python vol.py -f memory.dmp --profile=Win7SP1x64 psscan  # Scan for hidden processes

# Volatility 3
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.pstree
python3 vol.py -f memory.dmp windows.psscan
```

### Process Information

```bash
# Volatility 2
# Command line arguments
python vol.py -f memory.dmp --profile=Win7SP1x64 cmdline

# Process environment variables
python vol.py -f memory.dmp --profile=Win7SP1x64 envars -p <PID>

# DLLs loaded by process
python vol.py -f memory.dmp --profile=Win7SP1x64 dlllist -p <PID>

# Handles opened by process
python vol.py -f memory.dmp --profile=Win7SP1x64 handles -p <PID>

# Memory map
python vol.py -f memory.dmp --profile=Win7SP1x64 memmap -p <PID>

# Volatility 3
python3 vol.py -f memory.dmp windows.cmdline
python3 vol.py -f memory.dmp windows.envars --pid <PID>
python3 vol.py -f memory.dmp windows.dlllist --pid <PID>
python3 vol.py -f memory.dmp windows.handles --pid <PID>
```

### Dump Process Memory

```bash
# Volatility 2
# Dump process executable
python vol.py -f memory.dmp --profile=Win7SP1x64 procdump -p <PID> -D output/

# Dump process memory
python vol.py -f memory.dmp --profile=Win7SP1x64 memdump -p <PID> -D output/

# Dump all processes
python vol.py -f memory.dmp --profile=Win7SP1x64 procdump -D output/

# Volatility 3
python3 vol.py -f memory.dmp -o output/ windows.dumpfiles --pid <PID>
python3 vol.py -f memory.dmp -o output/ windows.memmap --pid <PID> --dump
```

## Network Analysis

### Network Connections

```bash
# Volatility 2
# Active connections (XP/2003)
python vol.py -f memory.dmp --profile=WinXPSP3x86 connections

# Active sockets (XP/2003)
python vol.py -f memory.dmp --profile=WinXPSP3x86 sockets

# Network connections (Vista+)
python vol.py -f memory.dmp --profile=Win7SP1x64 netscan

# Volatility 3
python3 vol.py -f memory.dmp windows.netscan
python3 vol.py -f memory.dmp windows.netstat
```

### Extract Network Artifacts

```bash
# IE history
python vol.py -f memory.dmp --profile=Win7SP1x64 iehistory

# Get URLs from memory
python vol.py -f memory.dmp --profile=Win7SP1x64 strings -s | grep -i "http://"
```

## Registry Analysis

### Registry Hives

```bash
# Volatility 2
# List registry hives
python vol.py -f memory.dmp --profile=Win7SP1x64 hivelist

# Print registry key
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Microsoft\Windows\CurrentVersion\Run"

# Get specific registry value
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion"

# Dump registry hive
python vol.py -f memory.dmp --profile=Win7SP1x64 dumpregistry -D output/

# Volatility 3
python3 vol.py -f memory.dmp windows.registry.hivelist
python3 vol.py -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Common Registry Keys to Check

```bash
# Autostart locations
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Services
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "System\CurrentControlSet\Services"

# Installed software
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Uninstall"

# USB devices
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "System\CurrentControlSet\Enum\USBSTOR"

# Recent documents
python vol.py -f memory.dmp --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
```

## Malware Detection

### Detect Malware

```bash
# Volatility 2
# Detect injected code
python vol.py -f memory.dmp --profile=Win7SP1x64 malfind

# Detect API hooks
python vol.py -f memory.dmp --profile=Win7SP1x64 apihooks

# Detect SSDT hooks
python vol.py -f memory.dmp --profile=Win7SP1x64 ssdt

# Detect IRP hooks
python vol.py -f memory.dmp --profile=Win7SP1x64 driverirp

# Detect kernel callbacks
python vol.py -f memory.dmp --profile=Win7SP1x64 callbacks

# Detect suspicious services
python vol.py -f memory.dmp --profile=Win7SP1x64 svcscan

# Volatility 3
python3 vol.py -f memory.dmp windows.malfind
python3 vol.py -f memory.dmp windows.ssdt
python3 vol.py -f memory.dmp windows.callbacks
```

### Rootkit Detection

```bash
# List kernel modules
python vol.py -f memory.dmp --profile=Win7SP1x64 modules

# Scan for hidden modules
python vol.py -f memory.dmp --profile=Win7SP1x64 modscan

# Detect hidden/unlinked processes
python vol.py -f memory.dmp --profile=Win7SP1x64 psxview

# Detect kernel hooks
python vol.py -f memory.dmp --profile=Win7SP1x64 ssdt
```

## File Extraction

### File System Analysis

```bash
# Volatility 2
# Scan for FILE_OBJECTs
python vol.py -f memory.dmp --profile=Win7SP1x64 filescan

# Dump specific file
python vol.py -f memory.dmp --profile=Win7SP1x64 dumpfiles -Q <physical_offset> -D output/

# Dump file by name (regex)
python vol.py -f memory.dmp --profile=Win7SP1x64 dumpfiles -r malware\.exe -D output/

# Dump all files
python vol.py -f memory.dmp --profile=Win7SP1x64 dumpfiles -D output/

# Volatility 3
python3 vol.py -f memory.dmp -o output/ windows.dumpfiles
python3 vol.py -f memory.dmp windows.filescan
```

### Extract Cached Files

```bash
# Extract executables from memory
python vol.py -f memory.dmp --profile=Win7SP1x64 dlldump -D output/

# Extract from specific process
python vol.py -f memory.dmp --profile=Win7SP1x64 dlldump -p <PID> -D output/
```

## Timeline Analysis

### Create Timeline

```bash
# Volatility 2
# MFT timeline
python vol.py -f memory.dmp --profile=Win7SP1x64 mftparser --output=body --output-file=timeline.body

# Shellbags timeline
python vol.py -f memory.dmp --profile=Win7SP1x64 shellbags --output=body --output-file=shellbags.body

# Timeliner (all timeline data)
python vol.py -f memory.dmp --profile=Win7SP1x64 timeliner --output=body --output-file=timeliner.body

# Volatility 3
python3 vol.py -f memory.dmp windows.mftscan
python3 vol.py -f memory.dmp timeliner
```

### Process Mactime Timeline

```bash
# Use mactime to create human-readable timeline
mactime -b timeline.body -d > timeline.csv
```

## Advanced Analysis

### User Activity

```bash
# Clipboard contents
python vol.py -f memory.dmp --profile=Win7SP1x64 clipboard

# Console history
python vol.py -f memory.dmp --profile=Win7SP1x64 consoles

# Notepad contents
python vol.py -f memory.dmp --profile=Win7SP1x64 notepad

# Screenshot (if GUI active)
python vol.py -f memory.dmp --profile=Win7SP1x64 screenshot -D output/
```

### Password Extraction

```bash
# Extract password hashes
python vol.py -f memory.dmp --profile=Win7SP1x64 hashdump

# LSA secrets
python vol.py -f memory.dmp --profile=Win7SP1x64 lsadump

# Cached domain credentials
python vol.py -f memory.dmp --profile=Win7SP1x64 cachedump

# Mimikatz-like extraction (Vol3)
python3 vol.py -f memory.dmp windows.hashdump
python3 vol.py -f memory.dmp windows.lsadump
```

### Master Boot Record

```bash
# Analyze MBR
python vol.py -f memory.dmp --profile=Win7SP1x64 mbrparser
```

### Yara Scanning

```bash
# Scan with Yara rules
python vol.py -f memory.dmp --profile=Win7SP1x64 yarascan -Y <rule_file>

# Scan specific process
python vol.py -f memory.dmp --profile=Win7SP1x64 yarascan -p <PID> -Y <rule_file>

# Scan for specific string
python vol.py -f memory.dmp --profile=Win7SP1x64 yarascan -y "malware_string"

# Volatility 3
python3 vol.py -f memory.dmp windows.vadyarascan --yara-rules <rule_file>
```

### String Search

```bash
# Extract strings
strings -a -td memory.dmp > strings_ascii.txt
strings -e l -td memory.dmp > strings_unicode.txt

# Search for specific strings
python vol.py -f memory.dmp --profile=Win7SP1x64 strings -s strings_ascii.txt | grep -i "password"
```

## Common Investigation Workflows

### Initial Triage

```bash
# 1. Identify OS
python vol.py -f memory.dmp imageinfo

# 2. List processes
python vol.py -f memory.dmp --profile=<profile> pslist

# 3. Check network connections
python vol.py -f memory.dmp --profile=<profile> netscan

# 4. Check for malware indicators
python vol.py -f memory.dmp --profile=<profile> malfind
```

### Malware Analysis

```bash
# 1. Find suspicious processes
python vol.py -f memory.dmp --profile=<profile> psxview

# 2. Check for code injection
python vol.py -f memory.dmp --profile=<profile> malfind

# 3. Check for hooks
python vol.py -f memory.dmp --profile=<profile> ssdt
python vol.py -f memory.dmp --profile=<profile> apihooks

# 4. Extract suspicious process
python vol.py -f memory.dmp --profile=<profile> procdump -p <PID> -D output/

# 5. Analyze DLLs
python vol.py -f memory.dmp --profile=<profile> dlllist -p <PID>
```

### Incident Response

```bash
# 1. Timeline of activity
python vol.py -f memory.dmp --profile=<profile> timeliner --output=body --output-file=timeline.body

# 2. User activity
python vol.py -f memory.dmp --profile=<profile> consoles
python vol.py -f memory.dmp --profile=<profile> clipboard
python vol.py -f memory.dmp --profile=<profile> cmdline

# 3. Network activity
python vol.py -f memory.dmp --profile=<profile> netscan

# 4. Persistence mechanisms
python vol.py -f memory.dmp --profile=<profile> printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
python vol.py -f memory.dmp --profile=<profile> svcscan

# 5. Extract evidence
python vol.py -f memory.dmp --profile=<profile> dumpfiles -D output/
```

## Volatility Plugins (Quick Reference)

### Process Memory
- `pslist` - List processes
- `pstree` - Process tree
- `psscan` - Scan for processes (including hidden)
- `psxview` - Find hidden processes
- `cmdline` - Command line arguments
- `dlllist` - DLLs loaded by processes
- `handles` - Open handles
- `getsids` - Security identifiers

### Network
- `netscan` - Scan for network connections (Vista+)
- `connections` - Active connections (XP/2003)
- `sockets` - Open sockets (XP/2003)
- `connscan` - Scan for connection structures

### Registry
- `hivelist` - List registry hives
- `printkey` - Print registry key
- `hivedump` - Dump registry hive
- `userassist` - UserAssist registry data
- `shimcache` - Application compatibility cache

### Malware
- `malfind` - Find injected code
- `apihooks` - Detect API hooks
- `ssdt` - Display SSDT
- `idt` - Display IDT
- `gdt` - Display GDT
- `callbacks` - List kernel callbacks
- `driverirp` - Driver IRP hooks
- `devicetree` - Device tree

### File System
- `filescan` - Scan for file objects
- `dumpfiles` - Extract files
- `mftparser` - MFT entries

### Misc
- `clipboard` - Extract clipboard
- `screenshot` - Take screenshot
- `timeliner` - Create timeline
- `imageinfo` - Image information

## Tips and Tricks

### Performance Optimization

```bash
# Use --kdbg for faster processing (if known)
python vol.py -f memory.dmp --profile=Win7SP1x64 --kdbg=0x... pslist

# Cache results
python vol.py -f memory.dmp --profile=Win7SP1x64 --cache-dtb pslist

# Output to file for analysis
python vol.py -f memory.dmp --profile=Win7SP1x64 pslist > processes.txt
```

### Bulk Analysis

```bash
# Create script for multiple plugins
#!/bin/bash
PROFILE="Win7SP1x64"
DUMP="memory.dmp"

python vol.py -f $DUMP --profile=$PROFILE pslist > pslist.txt
python vol.py -f $DUMP --profile=$PROFILE pstree > pstree.txt
python vol.py -f $DUMP --profile=$PROFILE netscan > netscan.txt
python vol.py -f $DUMP --profile=$PROFILE malfind > malfind.txt
```

## Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- [Memory Forensics Cheat Sheet](https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf)

## Legal Notice

⚠️ **WARNING**: Only analyze memory dumps from systems you own or have explicit permission to investigate. Unauthorized memory analysis may be illegal.

---

**Pro Tip**: Always start with `imageinfo` to identify the correct profile. An incorrect profile will produce unreliable results.

