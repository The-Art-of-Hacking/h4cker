# Linux commands and detection techniques for identifying rootkits and system compromise

The following is a comprehensive set of Linux commands and detection strategies for identifying rootkits and system compromise. This guide is organized from quick triage to deep forensic analysis. [kali](https://www.kali.org/tools/chkrootkit/)

***

## 1. Quick Triage Commands (Run First)

Start with these to get immediate signals:

```bash
# Check kernel taint status - indicates loaded kernel modules
cat /proc/sys/kernel/tainted
# 0 = clean; non-zero = kernel modules loaded (suspicious if you didn't load them)

# List loaded kernel modules
lsmod

# Compare with /proc/modules
cat /proc/modules

# Check for common rootkit signatures
sudo rkhunter -c --skip-keypress --report-warnings-only
sudo chkrootkit
```

If `cat /proc/sys/kernel/tainted` returns non-zero, suspect kernel-level rootkit activity. [youtube](https://www.youtube.com/watch?v=pZbEUHdwio8)

***

## 2. Process & Memory Analysis

### Find suspicious/hidden processes

```bash
# List all processes (check for odd names, processes with no TTY)
ps auxww | grep -v "^\[" | awk '{print $1, $11}'

# Find processes by PID space inconsistencies
# If a rootkit hides a process, you may see PID gaps
ls /proc | grep "^[0-9]" | sort -n

# Check process details
cat /proc/<PID>/status          # Look for VmPeak (memory), VmRSS, threads
cat /proc/<PID>/cmdline         # Actual command line (null-separated)
cat /proc/<PID>/environ         # Environment variables (look for LD_PRELOAD, PATH hijacks)
cat /proc/<PID>/maps            # Memory mapping (detect code injection)
cat /proc/<PID>/fd              # Open file descriptors (what's it accessing?)
cat /proc/<PID>/net/tcp         # Network connections from this process

# Check for open files without a process
# Rootkits may delete files but keep them open
lsof | grep deleted

# Check for processes with unusual characteristics
ps aux | awk '$3 > 50 {print}'  # CPU > 50%
ps aux | awk '$4 > 50 {print}'  # Memory > 50%

# Look for processes in /tmp or unusual directories
ps aux | grep -E '(/tmp|/dev/shm|/var/tmp)'

# Find kthreads spawning user-space commands (highly suspicious)
ps aux | grep '\[' | head  # Kernel threads have brackets; if one spawned a shell, it's fishy
```

### Memory forensics (requires memory dump tools)

```bash
# If Volatility is installed
volatility -f /path/to/memory.dump linux_pslist      # Hidden processes
volatility -f /path/to/memory.dump linux_network    # Network connections
volatility -f /path/to/memory.dump linux_modules    # Loaded kernel modules
```

***

## 3. Kernel Module & Rootkit Checks

### Detect kernel-level rootkits (the most dangerous)

```bash
# Check loaded modules and their taint flags
cat /sys/module/*/taint
# Non-zero = tainted module (may indicate rootkit injection)

# Compare lsmod vs /proc/modules (rootkit may hide in one but not the other)
diff <(lsmod | awk '{print $1}' | sort) <(cat /proc/modules | awk '{print $1}' | sort)

# Check for hidden modules
ls /sys/module
# Compare against lsmod output for discrepancies

# Scan for specific rootkit signatures
sudo rkhunter -c --check-root-accounts --check-default-umask
sudo chkrootkit

# Check if kernel has suspicious eBPF programs (modern rootkits use eBPF)
sudo bpftool map list
sudo bpftool prog list
dmesg | grep -i bpf

# Check for systemtap or eBPF hooks (modern rootkit persistence)
dmesg | grep -i systemtap
dmesg | grep -i "bpf_probe_write_user"
```

***

## 4. File Integrity & Filesystem Analysis

```bash
# Find recently modified files (last 24 hours)
find / -type f -mtime -1 2>/dev/null | head -50

# Find recently modified SYSTEM files (more suspicious)
find /bin /sbin /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null

# Find files whose METADATA changed (ctime) - rootkits often touch this
find / -type f -ctime -1 2>/dev/null

# Compare modification time (mtime) vs metadata change time (ctime)
# If ctime is recent but mtime is old → rootkit may have touched it
find /bin -type f -printf "%T@ %C@ %p\n" | awk '$1 != $2 {print $3}' | head

# Find immutable files (some rootkits set these)
lsattr -R /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -i immutable

# Look for hidden files in system directories (ls -l vs ls -la discrepancy)
diff <(ls /bin | wc -l) <(ls -a /bin | wc -l)
# If numbers differ, hidden files exist

# Byte-count check (rootkit hiding files shows size mismatch)
ls -la /etc/modules | awk '{print $5}'  # Byte size
wc -c < /etc/modules                     # Actual byte size
# Mismatch indicates hidden content

# Use dd or od to read hidden file content that rootkit is scrubbing
dd if=/etc/modules bs=1 | od -c | grep -v "^0"

# Or use grep to bypass file-hiding rootkit filters
grep "." /etc/modules  # This may show hidden lines

# Check for suspicious hardlinks or symlinks
find / -type f -perm /u+s,g+s 2>/dev/null  # SUID/SGID files (privilege escalation vectors)
find / -type l 2>/dev/null | head           # Symlinks (can point to rootkit binaries)
```

***

## 5. LD_PRELOAD & Library Hijacking Checks

Rootkits often hook system calls via LD_PRELOAD or by replacing libraries. [pcmag](https://www.pcmag.com/explainers/how-to-check-your-security-software-settings-and-status)

```bash
# Check LD_PRELOAD in system environment
cat /etc/ld.so.preload 2>/dev/null
# Should be empty; if it has entries, investigate each

# Check all preload entries globally
grep -r "LD_PRELOAD" /etc /var /home 2>/dev/null

# Check for suspicious entries in /etc/ld.so.conf.d/
ls -la /etc/ld.so.conf.d/
cat /etc/ld.so.conf.d/*.conf

# Find which libraries are loaded by a process
ldd /usr/bin/ls
# Compare against a clean system to spot library hijacking

# Check for replaced system libraries
find /lib /lib64 /usr/lib -name "*.so*" -type f -newer /etc/issue 2>/dev/null

# Verify library integrity against package manager
# Debian/Ubuntu:
sudo debsums -c          # Check package file integrity against installed packages

# RHEL/CentOS:
sudo rpm -V $(rpm -qa)   # Verify all packages
```

***

## 6. Network & Connection Analysis

```bash
# List all listening ports
sudo netstat -tulnp
sudo ss -tulnp
sudo lsof -i -P -n | grep LISTEN

# Show established connections
netstat -tanp | grep ESTABLISHED
ss -tanp | grep ESTABLISHED

# Check for unexpected listeners on high ports
netstat -tulnp | grep -E ':(4444|1337|8080|6666|31337)'

# Look for connections from unusual processes/users
netstat -anp | grep -E 'sshd|httpd|smtp' | grep -v "^(tcp|unix)"

# Check for suspicious reverse shells
netstat -anp | grep -v LISTEN | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u

# Find processes with unusual file descriptors open to TCP
lsof -i TCP -a -u root -u syslog

# Check arp cache for poison (MITM attacks)
arp -a
# Look for duplicate MAC addresses or suspicious IPs
```

***

## 7. Authentication & Access Logs

```bash
# Check login logs for unusual access times or sources
tail -100 /var/log/auth.log | grep "Accepted\|Failed"

# Look for brute-force attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Check for sudo abuse
grep "sudo:" /var/log/auth.log | tail -50

# Look for new user accounts (rootkit may create backdoor user)
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd

# Check for UID 0 accounts (root access)
awk -F: '$3 == 0 {print $1}' /etc/passwd
# Should only be "root"; others are backdoors

# Check for password changes
grep "password changed" /var/log/auth.log

# Analyze systemd journal (newer systems)
journalctl -u ssh --since "1 hour ago"
journalctl -u sudo --since "1 hour ago"
```

***

## 8. Startup & Persistence Mechanisms

```bash
# Check system startup files
ls -la /etc/init.d/
ls -la /etc/rc.d/
cat /etc/rc.local           # Often abused for persistence
cat /etc/inittab            # Check for spawned shells

# Systemd services (modern systems)
systemctl list-units --type=service --all
systemctl list-timers --all  # Timer units that run periodically

# Check specific suspicious service files
find /etc/systemd -name "*.service" -exec grep -l "ExecStart" {} \;

# Cron jobs
crontab -l                  # User crontabs
sudo crontab -l             # Root crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/

# Check for at jobs
sudo atq
sudo at -l

# SSH authorized_keys (look for backdoor SSH keys)
find /home /root -name "authorized_keys" -exec cat {} \;
# Compare against known keys; extra keys = backdoor

# Shell startup files (may contain LD_PRELOAD or aliases)
cat /etc/profile
cat /etc/bashrc
cat ~/.bashrc ~/.bash_profile ~/.zshrc
# Look for suspicious exports, aliases, or function definitions

# SSH config (may have backdoor entries)
cat /etc/ssh/sshd_config
# Check for suspicious PermitRootLogin, AllowUsers, Match conditions
```

***

## 9. Dedicated Rootkit Scanner Tools

### Install and run comprehensive scanners

```bash
# Rootkit Hunter (signature-based)
sudo apt-get install rkhunter          # Debian/Ubuntu
sudo yum install rkhunter              # RHEL/CentOS
sudo rkhunter -u                        # Update database
sudo rkhunter -c --skip-keypress       # Full scan

# Chkrootkit (heuristic-based)
sudo apt-get install chkrootkit
sudo chkrootkit 2>&1 | tee chkrootkit_report.txt

# AIDE (file integrity)
sudo apt-get install aide aide-common
sudo aideinit                           # Create baseline
sudo aide -C                            # Compare against baseline
```

### For advanced kernel rootkit detection

```bash
# OSSEC (host-based intrusion detection)
sudo apt-get install ossec-hids

# Lynis (system hardening audit, includes rootkit checks)
sudo apt-get install lynis
sudo lynis audit system

# Auditd (kernel-level audit logging)
sudo apt-get install auditd audispd-plugins
sudo auditctl -l                        # List audit rules
sudo ausearch -k rootkit                # Search for rootkit-related events
```

***

## 10. Advanced: Inconsistency Detection

The most sophisticated rootkits hide processes/files from userland tools but can't hide from kernel/filesystem reads. Use **inconsistency checks**: [youtube](https://www.youtube.com/watch?v=pZbEUHdwio8)

```bash
# Byte count mismatch test
# If a file shows size X via ls but wc shows different byte count, rootkit is hiding content
for file in /etc/modules /etc/shadow; do
    size=$(ls -la "$file" | awk '{print $5}')
    actual=$(wc -c < "$file")
    if [ "$size" != "$actual" ]; then
        echo "MISMATCH: $file ls=$size wc=$actual (ROOTKIT LIKELY)"
    fi
done

# Compare outputs from different tools
# If ps and /proc disagree on process list, rootkit hides processes
diff <(ps aux | awk '{print $2}' | sort -n) <(ls /proc | grep '^[0-9]' | sort -n)

# Check for discrepancies between lsof and netstat
sudo diff <(lsof -i | grep LISTEN | awk '{print $9}' | sort) \
          <(netstat -tulnp | grep LISTEN | awk '{print $4}' | sort)

# Read file with different tools; if outputs differ, rootkit filters one
ls -l /var/log/syslog
cat /var/log/syslog | wc -l
grep "." /var/log/syslog | wc -l    # Rootkit may filter ls but not grep

# dd to read raw bytes and bypass filters
dd if=/var/log/auth.log bs=1 | od -c | tail -20
```

***

## 11. Forensic Timeline Analysis

```bash
# Create detailed timeline of file modifications
find / -type f -newermt "2025-01-10" ! -newermt "2025-01-15" 2>/dev/null | while read file; do
    stat "$file" | grep -E "Modify|Change|Access"
done > /tmp/timeline.txt

# Correlate with process execution
# Extract commands from bash history with timestamps
grep "^#" ~/.bash_history | while read ts; do
    date -d @${ts:1}
done

# Check for log tampering (logs with gaps or reversed timestamps)
awk '{print $1, $2, $3}' /var/log/syslog | uniq -c | grep -v "^ *1 "
```

***

## 12. Containment & Isolation Steps (If Compromise Detected)

```bash
# Immediately isolate the system
sudo ip link set eth0 down              # Disconnect network
sudo systemctl stop networking          # Or full network shutdown

# Kill suspicious processes (be careful!)
sudo kill -9 <suspicious_PID>

# Prevent persistence
sudo systemctl disable <suspicious_service>
sudo rm /etc/cron.d/<suspected_cron>
sudo rm /etc/systemd/system/<suspected_service>

# Preserve evidence before reboot
sudo tar -czf /tmp/forensics_$(date +%s).tar.gz /var/log /home /root 2>/dev/null
# Copy to external media if possible

# If deep compromise detected: rebuild from known-good media
# Full OS reinstall is the only guaranteed removal for kernel rootkits
```

***

## 13. Proactive Monitoring (Before Compromise)

Set up these checks to run regularly: [learn.microsoft](https://learn.microsoft.com/en-us/answers/questions/4110281/i-need-to-know-if-my-laptop-is-safe)

```bash
# Create a baseline of clean system state
sudo rkhunter --update --skip-keypress
sudo rkhunter -c --skip-keypress > /root/rkhunter_baseline.txt

# Monitor file integrity with AIDE
sudo aideinit
sudo aide --config=/etc/aide/aide.conf.d/aide.conf > /root/aide_baseline.txt

# Weekly check script
#!/bin/bash
echo "=== Rootkit scan ===" >> /var/log/security_check.log
sudo rkhunter -c --skip-keypress >> /var/log/security_check.log 2>&1
sudo chkrootkit >> /var/log/security_check.log 2>&1
echo "=== AIDE check ===" >> /var/log/security_check.log
sudo aide --config=/etc/aide/aide.conf.d/aide.conf -C >> /var/log/security_check.log 2>&1

# Add to crontab
(sudo crontab -l 2>/dev/null; echo "0 2 * * 0 /usr/local/bin/security_check.sh") | sudo crontab -
```

***

## Quick Triage Decision Tree

```
1. Run: cat /proc/sys/kernel/tainted
   → If 0: likely clean (but not guaranteed)
   → If non-zero: kernel modules loaded; verify with lsmod

2. Run: sudo rkhunter -c --skip-keypress
   → If FOUND: you have a known rootkit; isolate immediately

3. Run: ps auxww | grep -v "^\[" | wc -l
   → Compare PIDs in /proc to check for hidden processes

4. Run: netstat -anp | grep ESTABLISHED
   → Look for unexpected outbound connections

5. Run: find /bin /sbin /usr/bin -mtime -1
   → Check for recently modified system binaries

6. If any checks fail: ISOLATE, PRESERVE LOGS, REBUILD FROM CLEAN MEDIA
```

***

## Advanced Detection Insights

1. **Kernel-level rootkits are the hardest to detect** – they control what the OS reports. Compare tools (`ps` vs `/proc`, `lsof` vs `netstat`) for discrepancies.

2. **Byte-count mismatches reveal hidden files** – if `ls` shows 283 bytes but `wc` shows more, the rootkit is hiding content. Use `grep "."` or `dd` to bypass filtering.

3. **eBPF rootkits are the newest threat** – check `bpftool prog list` and `dmesg | grep bpf` for modern hook mechanisms.

4. **Persistence is key** – check systemd services, cron, LD_PRELOAD, /etc/rc.local, and SSH keys obsessively.

5. **Full rebuild is the only guarantee** – if kernel-level compromise is confirmed, treat as a full system loss and reinstall from official media.

Consider using **eBPF-based detection tools** such as **Tetragon** (Cilium's threat detection) and **Osquery** for continuous monitoring at scale.
