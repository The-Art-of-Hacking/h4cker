# macOS commands and detection techniques for identifying rootkits and system compromise

The following is a comprehensive set of macOS commands and detection strategies for identifying rootkits and system compromise. This guide is organized from quick triage to deep forensic analysis.

***

## 1. Quick Triage Commands (Run First)

Start with these to get immediate signals:

```bash
# Check system integrity protection (SIP) status
csrutil status
# Expected: "System Integrity Protection status: enabled"
# If disabled, system may be compromised

# Check for unsigned kernel extensions
kextstat | grep -v com.apple
# Look for non-Apple KEXTs (kernel extensions)

# List all loaded kernel extensions with details
kextstat -l

# Check kernel extension signing status
sudo kextcache -system-prelinked-kernel
sudo kextcache -system-caches

# Verify gatekeeper status (prevents unsigned apps)
spctl --status
# Expected: "assessments enabled"

# Check for modifications to critical system files
sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check

# Quick check for common persistence locations
sudo ls -la /Library/LaunchDaemons/
sudo ls -la /Library/LaunchAgents/
ls -la ~/Library/LaunchAgents/
```

***

## 2. Process & Memory Analysis

### Find suspicious/hidden processes

```bash
# List all running processes with full details
ps auxww | less

# Check for processes with suspicious characteristics
ps aux | awk '$3 > 50 {print}'  # CPU > 50%
ps aux | awk '$4 > 50 {print}'  # Memory > 50%

# Look for processes without TTY (background processes)
ps aux | grep "?" | grep -v "\["

# Find processes running from unusual locations
ps aux | grep -E '(/tmp|/private/tmp|/var/tmp|/dev)'

# Check for processes with odd parent-child relationships
ps -axj | less

# List all processes with their full command line
ps -axo pid,ppid,user,%cpu,%mem,start,command | less

# Check process details using Activity Monitor command line
top -l 1 -stats pid,command,cpu,mem,threads

# Find processes with open network connections
sudo lsof -i -P -n
sudo lsof -i TCP -s TCP:LISTEN

# Check for processes accessing sensitive files
sudo lsof | grep -E "(password|shadow|sudoers|ssh|private)"

# List all processes by user
ps aux | awk '{print $1}' | sort | uniq -c | sort -rn

# Check for hidden processes (compare ps with proc)
ls /proc 2>/dev/null || echo "No /proc on macOS, use alternative methods"
# macOS doesn't use /proc the same way Linux does
```

### Advanced process inspection

```bash
# Get detailed process information
ps -p <PID> -o pid,ppid,user,args,start,etime,%cpu,%mem

# Check process binary location and signature
ps aux | awk '{print $11}' | sort -u
# Then verify each binary:
codesign -dv --verbose=4 /path/to/binary 2>&1

# List all open files for a process
sudo lsof -p <PID>

# Check process environment variables
sudo ps eww <PID>

# Inspect process memory regions (requires debugging)
sudo vmmap <PID> | less

# Check for dyld environment variables (dylib injection)
sudo launchctl print system | grep DYLD
sudo launchctl print user/$(id -u) | grep DYLD
```

***

## 3. Kernel Extension & Rootkit Checks

### Detect kernel-level rootkits

```bash
# List all loaded kernel extensions
kextstat

# Check for unsigned or suspicious kernel extensions
kextstat | grep -v "com.apple" | grep -v "com.intel"

# Get detailed information about specific KEXT
kextstat -l -b com.suspicious.kext

# Find all KEXTs on disk (loaded and unloaded)
sudo find /System/Library/Extensions -name "*.kext" -type d
sudo find /Library/Extensions -name "*.kext" -type d

# Check KEXT signatures and notarization
sudo kextutil -n -t /System/Library/Extensions/SomeKext.kext
codesign -dv --verbose=4 /path/to/suspicious.kext

# Verify kernel extension is properly signed
spctl -a -v -t install /Library/Extensions/SomeKext.kext

# Check system extensions (modern replacement for KEXTs)
systemextensionsctl list

# List endpoint security clients
sudo launchctl list | grep -i security

# Check for legacy KEXTs that shouldn't be present on modern macOS
ls -la /Library/Extensions/
# On macOS 11+, user-installed KEXTs are deprecated
```

### Firmware and boot security

```bash
# Check firmware integrity (EFI)
sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check
sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --show-hashes

# Verify secure boot status (Apple Silicon)
sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check

# Check boot-args for suspicious modifications
nvram boot-args
# Should typically be empty or contain only expected values

# List all NVRAM variables
nvram -p

# Check for modified boot ROM version
system_profiler SPiBridgeDataType
system_profiler SPiBridgeDataType | grep "Boot ROM Version"
```

***

## 4. File System & Persistence Analysis

### Common persistence locations

```bash
# Launch Daemons (system-wide, run as root)
sudo ls -lah /Library/LaunchDaemons/
sudo ls -lah /System/Library/LaunchDaemons/

# Launch Agents (per-user)
ls -lah /Library/LaunchAgents/
ls -lah ~/Library/LaunchAgents/
ls -lah /System/Library/LaunchAgents/

# Check for suspicious launch items
sudo launchctl list
launchctl list

# Examine specific launch item
sudo launchctl print system/com.suspicious.service
launchctl print gui/$(id -u)/com.suspicious.agent

# Startup Items (legacy, pre-10.10)
ls -la /Library/StartupItems/
ls -la /System/Library/StartupItems/

# Login Items (per-user)
osascript -e 'tell application "System Events" to get the name of every login item'

# Periodic scripts
ls -la /etc/periodic/daily/
ls -la /etc/periodic/weekly/
ls -la /etc/periodic/monthly/

# Cron jobs
crontab -l
sudo crontab -l
ls -la /usr/lib/cron/tabs/

# Check for hidden cron jobs in other user accounts
sudo ls -la /var/at/tabs/
sudo ls -la /usr/lib/cron/tabs/
```

### Browser extensions and plugins

```bash
# Safari extensions
ls -la ~/Library/Safari/Extensions/

# Chrome extensions
ls -la ~/Library/Application\ Support/Google/Chrome/Default/Extensions/

# Firefox addons
ls -la ~/Library/Application\ Support/Firefox/Profiles/*.default*/extensions/

# System-wide browser plugins
ls -la /Library/Internet\ Plug-Ins/
ls -la ~/Library/Internet\ Plug-Ins/
```

### File system modifications

```bash
# Find recently modified system files
sudo find /usr /System -type f -mtime -7 -ls 2>/dev/null | head -50

# Find SUID/SGID files (potential privilege escalation)
sudo find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Look for hidden files in unusual locations
sudo find /var /tmp /private -name ".*" -ls 2>/dev/null

# Check for files with unusual attributes
sudo ls -lO /usr/bin /usr/sbin | grep -E "(schg|uschg|sappnd|uappnd)"

# Find files modified after system installation date
system_profiler SPSoftwareDataType | grep "Time since boot"
# Then use: sudo find / -newer /var/db/.AppleSetupDone 2>/dev/null

# Check for suspicious dynamic libraries
sudo find /usr/lib /usr/local/lib /Library -name "*.dylib" -mtime -30

# Look for dylib hijacking opportunities
# Check for missing libraries that programs try to load
sudo fs_usage | grep dylib &
# Run for a few minutes and look for ENOENT (file not found) errors
```

### Check critical system files

```bash
# Verify system file integrity
sudo /usr/libexec/repair_packages --verify --standard-pkgs

# Check sudoers file
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/

# Check hosts file
cat /etc/hosts

# Check PAM configuration
ls -la /etc/pam.d/

# Verify SSH configuration
cat /etc/ssh/sshd_config
ls -la ~/.ssh/

# Check for SSH keys
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys

# Check shell profiles for malicious modifications
cat ~/.bash_profile ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null | grep -v "^#" | grep .
```

***

## 5. Network & System Monitoring

### Network connections and listeners

```bash
# List all listening ports
sudo lsof -iTCP -sTCP:LISTEN -n -P
sudo lsof -iUDP -n -P

# Show all network connections with process info
sudo lsof -i -n -P

# Check for established connections
netstat -an | grep ESTABLISHED

# List network connections by process
sudo lsof -i -P | grep -i "established"

# Check packet filter (firewall) configuration
sudo pfctl -sr
sudo pfctl -sn
sudo pfctl -sa

# View firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# Check DNS configuration
scutil --dns
cat /etc/resolv.conf

# List network interfaces
ifconfig -a
networksetup -listallnetworkservices

# Check for proxy configuration
scutil --proxy
networksetup -getwebproxy Wi-Fi
networksetup -getsecurewebproxy Wi-Fi
```

### System logs analysis

```bash
# View system logs
log show --predicate 'eventMessage contains "error" or eventMessage contains "fail"' --last 1h
log show --predicate 'processImagePath contains "/tmp" or processImagePath contains "/var/tmp"' --last 24h

# Check authentication logs
log show --predicate 'process == "sudo"' --last 1d
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h

# Check kernel extension loading events
log show --predicate 'eventMessage contains "kext"' --last 7d

# View security events
log show --predicate 'subsystem == "com.apple.security" or subsystem == "com.apple.securityd"' --last 1d

# Check for suspicious process launches
log show --predicate 'eventMessage contains "exec"' --last 1h | grep -v com.apple

# Legacy system logs (older macOS versions)
ls -la /var/log/
sudo cat /var/log/system.log
sudo tail -1000 /var/log/install.log
```

***

## 6. Security Tools & Verification

### Built-in security tools

```bash
# Run XProtect malware scan
sudo /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect

# Check quarantine attribute on files (Gatekeeper)
xattr -l /path/to/suspicious/file
# Look for: com.apple.quarantine

# Remove quarantine attribute (if needed for testing)
xattr -d com.apple.quarantine /path/to/file

# Check for code signing and notarization
codesign -dv --verbose=4 /Applications/SuspiciousApp.app
spctl --assess --verbose=4 /Applications/SuspiciousApp.app

# Verify system integrity
sudo /usr/libexec/repair_packages --verify --standard-pkgs

# Check FileVault status
sudo fdesetup status

# Verify secure enclave and T2 chip status (Intel Macs)
system_profiler SPiBridgeDataType

# Check Transparency Consent and Control (TCC) database
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"
```

### Third-party security tools

```bash
# KnockKnock - persistent software detector
# https://objective-see.com/products/knockknock.html
# Scans for persistent malware

# BlockBlock - monitors persistence locations
# https://objective-see.com/products/blockblock.html

# KextViewr - kernel extension viewer
# https://objective-see.com/products/kextviewr.html

# Netiquette - network monitor
# https://objective-see.com/products/netiquette.html

# Process Monitor - monitors process creation
# https://objective-see.com/products/utilities.html

# ReiKey - keyboard event monitor
# https://objective-see.com/products/reikey.html

# LuLu - firewall application
# https://objective-see.com/products/lulu.html

# Using rkhunter (if installed via Homebrew)
brew install rkhunter
sudo rkhunter --update
sudo rkhunter --check --skip-keypress

# Using OSSEC (if installed)
# https://www.ossec.net/
# Provides rootkit detection capabilities

# Using osquery for investigation
# https://osquery.io/
osqueryi
# Then run queries like:
# SELECT * FROM kernel_extensions WHERE name NOT LIKE '%apple%';
# SELECT * FROM listening_ports WHERE address != '127.0.0.1';
# SELECT * FROM launchd WHERE name NOT LIKE '%apple%';
```

***

## 7. Advanced Detection Techniques

### Endpoint Detection and Response (EDR)

```bash
# Check for EDR/AV software presence
ps aux | grep -iE "(carbon|crowd|sentinel|defender|edr|xdr)"
ls -la /Library/Application\ Support/ | grep -iE "(carbon|crowd|sentinel|defender)"

# Verify EDR agents are running
sudo launchctl list | grep -iE "(carbon|crowd|sentinel|defender)"

# Check system extensions for security tools
systemextensionsctl list
```

### Memory analysis

```bash
# Dump process memory (requires root)
sudo gcore <PID>
# Creates a core dump in /cores/

# Analyze with tools like:
# - Volatility (with macOS profile)
# - OSXPMem
# - rekall

# Check for dylib injection in running processes
sudo vmmap <PID> | grep -v "com.apple"
sudo vmmap <PID> | grep -E "(libhook|inject|payload)"
```

### Behavioral analysis

```bash
# Monitor file system events in real-time
sudo fs_usage -w | grep -v com.apple

# Monitor process execution
sudo dtrace -n 'proc:::exec-success { printf("%s %s", execname, curpsinfo->pr_psargs); }'

# Monitor network activity
sudo tcpdump -i en0 -n -c 100

# Watch for new kernel extensions
sudo fs_usage -w -f filesys | grep -E "kext|extension"

# Monitor library loading
sudo dtrace -n 'pid$target:libSystem*:dlopen:entry { printf("%s", copyinstr(arg0)); }' -p <PID>

# Trace system calls from suspicious process
sudo dtruss -p <PID> 2>&1 | tee dtruss.log
```

### Integrity verification

```bash
# Compare installed software with known-good baseline
system_profiler SPApplicationsDataType > current_apps.txt
# Compare with previous baseline

# Verify system files match expected checksums
sudo /usr/libexec/repair_packages --verify --standard-pkgs

# Check for modified system binaries
sudo find /usr/bin /usr/sbin -type f -exec shasum -a 256 {} \; > system_hashes.txt
# Compare with known-good baseline

# Verify all installed packages
pkgutil --pkgs | while read pkg; do 
    echo "=== $pkg ==="
    pkgutil --verify $pkg
done
```

### Persistence mechanisms

```bash
# Check for at jobs (rare on macOS but possible)
sudo atq
sudo ls -la /var/at/tabs/

# Check for authorization plugins
ls -la /Library/Security/SecurityAgentPlugins/

# Check for directory services plugins
ls -la /Library/DirectoryServices/PlugIns/

# Check for preference panes
ls -la /Library/PreferencePanes/
ls -la ~/Library/PreferencePanes/

# Check for Quick Look plugins
ls -la /Library/QuickLook/
ls -la ~/Library/QuickLook/

# Check for Spotlight importers
ls -la /Library/Spotlight/
ls -la ~/Library/Spotlight/

# Check for input methods
ls -la /Library/Input\ Methods/
ls -la ~/Library/Input\ Methods/

# Check for screen savers
ls -la /Library/Screen\ Savers/
ls -la ~/Library/Screen\ Savers/
```

***

## 8. Incident Response Checklist

When you suspect a compromise:

1. **Document everything** - Take screenshots, save command outputs
2. **Preserve volatile data** - Memory, running processes, network connections
3. **Isolate the system** - Disconnect from network if necessary
4. **Do NOT shut down** - May lose valuable forensic evidence
5. **Create forensic image** - Use tools like dd, Carbon Copy Cloner, or commercial solutions
6. **Collect logs** - System logs, application logs, security logs
7. **Analyze persistence** - Check all auto-start locations
8. **Review network activity** - Historical and current connections
9. **Check for lateral movement** - Review network logs, other systems
10. **Contact security team** - Follow organizational incident response procedures

***

## 9. Preventive Measures

### Hardening recommendations

```bash
# Enable System Integrity Protection (if disabled)
# Requires reboot into Recovery Mode
# csrutil enable

# Enable FileVault disk encryption
sudo fdesetup enable

# Enable firmware password
# Requires reboot into Recovery Mode
# firmwarepasswd -setpasswd

# Disable unnecessary services
sudo launchctl unload /System/Library/LaunchDaemons/com.suspicious.plist

# Keep system updated
softwareupdate -l
sudo softwareupdate -i -a

# Verify and enforce Gatekeeper
sudo spctl --master-enable
sudo spctl --enable

# Review and limit TCC permissions
# System Preferences > Security & Privacy > Privacy

# Enable firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Disable guest account
sudo dscl . -delete /Users/Guest

# Require administrator password for system-wide changes
# System Preferences > Security & Privacy > Advanced
```

***

## 10. References and Resources

### Official Apple Security Resources
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Apple Security Updates](https://support.apple.com/en-us/HT201222)
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)

### Tools and Frameworks
- [Objective-See Tools](https://objective-see.com/products.html) - Free macOS security tools
- [osquery](https://osquery.io/) - OS instrumentation framework
- [OSSEC](https://www.ossec.net/) - Host-based intrusion detection
- [Santa](https://github.com/google/santa) - Binary authorization system for macOS
- [OpenBSM](https://www.trustedbsd.org/openbsm.html) - Security audit subsystem

### Community Resources
- [macOS Security Awesome List](https://github.com/kai5263499/osx-security-awesome)
- [Mac4n6 - macOS Forensics](https://www.mac4n6.com/)
- [Sarah Edwards Research](https://www.mac4n6.com/)

### Detection Rules and Signatures
- [MITRE ATT&CK - macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Sigma Rules for macOS](https://github.com/SigmaHQ/sigma/tree/master/rules/macos)
- [YARA Rules for macOS Malware](https://github.com/Yara-Rules/rules/tree/master/malware)

***

## Important Notes

1. **Always use sudo carefully** - Many of these commands require elevated privileges
2. **Document your baseline** - Know what "normal" looks like on your systems
3. **False positives are common** - Not everything unusual is malicious
4. **Context matters** - Consider the environment and expected software
5. **Legal considerations** - Ensure you have authorization to perform these checks
6. **Privacy concerns** - Be mindful of user privacy when collecting data
7. **Apple Silicon vs Intel** - Some commands and paths differ between architectures
8. **macOS version differences** - Features and paths vary across macOS versions

***

*Last updated: February 2026*
*This guide is for educational and authorized security testing purposes only.*
