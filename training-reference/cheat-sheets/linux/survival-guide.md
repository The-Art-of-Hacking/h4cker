# Linux Survival Guide for Cybersecurity

A comprehensive guide to essential Linux commands and techniques for cybersecurity professionals.

## 📋 Table of Contents
- [Linux Survival Guide for Cybersecurity](#linux-survival-guide-for-cybersecurity)
  - [📋 Table of Contents](#-table-of-contents)
  - [File System Navigation](#file-system-navigation)
  - [File Operations](#file-operations)
  - [Text Processing](#text-processing)
  - [Process Management](#process-management)
  - [User Management](#user-management)
  - [Permissions](#permissions)
  - [Networking](#networking)
  - [System Information](#system-information)
  - [Package Management](#package-management)
    - [Debian/Ubuntu (APT)](#debianubuntu-apt)
    - [Red Hat/CentOS (YUM/DNF)](#red-hatcentos-yumdnf)
  - [Archiving and Compression](#archiving-and-compression)
  - [Security Commands](#security-commands)
  - [Essential Shortcuts](#essential-shortcuts)
  - [Piping and Redirection](#piping-and-redirection)
  - [Resources](#resources)

## File System Navigation

```bash
# Print working directory
pwd

# List directory contents
ls                    # Basic listing
ls -l                 # Long format
ls -la                # Include hidden files
ls -lh                # Human-readable sizes
ls -ltr               # Sort by time, reverse
ls -lSr               # Sort by size, reverse

# Change directory
cd /path/to/directory
cd ~                  # Home directory
cd -                  # Previous directory
cd ..                 # Parent directory
cd ../..              # Two levels up

# Tree view
tree                  # Directory tree
tree -L 2             # Limit depth to 2 levels
tree -d               # Directories only
```

## File Operations

```bash
# Create file
touch file.txt
echo "content" > file.txt

# Create directory
mkdir directory
mkdir -p path/to/nested/directory

# Copy files
cp source.txt dest.txt
cp -r source_dir/ dest_dir/     # Recursive
cp -p file.txt backup/          # Preserve attributes
cp -v file.txt backup/          # Verbose

# Move/Rename files
mv old_name.txt new_name.txt
mv file.txt /path/to/destination/

# Remove files
rm file.txt
rm -r directory/                # Recursive
rm -rf directory/               # Force remove
rm -i file.txt                  # Interactive

# Find files
find /path -name "*.txt"
find /path -type f -name "*.log"
find /path -mtime -7            # Modified in last 7 days
find /path -size +100M          # Files larger than 100MB
find /path -user username       # Files owned by user

# Locate files (faster, uses database)
locate filename
sudo updatedb                   # Update locate database

# Which (find executable)
which python
which -a python                 # All occurrences
```

## Text Processing

```bash
# View file contents
cat file.txt                    # Display entire file
less file.txt                   # Paginated view
more file.txt                   # Paginated view (older)
head file.txt                   # First 10 lines
head -n 20 file.txt             # First 20 lines
tail file.txt                   # Last 10 lines
tail -n 20 file.txt             # Last 20 lines
tail -f file.log                # Follow file (live updates)

# Search in files
grep "pattern" file.txt
grep -i "pattern" file.txt      # Case insensitive
grep -r "pattern" directory/    # Recursive search
grep -v "pattern" file.txt      # Invert match
grep -n "pattern" file.txt      # Show line numbers
grep -c "pattern" file.txt      # Count matches
grep -E "regex" file.txt        # Extended regex
grep -A 3 "pattern" file.txt    # Show 3 lines after
grep -B 3 "pattern" file.txt    # Show 3 lines before
grep -C 3 "pattern" file.txt    # Show 3 lines context

# AWK (text processing)
awk '{print $1}' file.txt       # Print first column
awk -F: '{print $1}' /etc/passwd # Custom delimiter
awk '/pattern/ {print $0}' file.txt

# SED (stream editor)
sed 's/old/new/' file.txt       # Replace first occurrence
sed 's/old/new/g' file.txt      # Replace all occurrences
sed -i 's/old/new/g' file.txt   # Edit in place
sed '/pattern/d' file.txt       # Delete lines matching pattern
sed -n '10,20p' file.txt        # Print lines 10-20

# CUT (extract columns)
cut -d: -f1 /etc/passwd         # First field, : delimiter
cut -c1-10 file.txt             # Characters 1-10

# SORT
sort file.txt                   # Alphabetical sort
sort -n file.txt                # Numeric sort
sort -r file.txt                # Reverse sort
sort -u file.txt                # Unique values
sort -k 2 file.txt              # Sort by column 2

# UNIQ (remove duplicates)
sort file.txt | uniq            # Remove adjacent duplicates
sort file.txt | uniq -c         # Count occurrences
sort file.txt | uniq -d         # Show only duplicates

# WC (word count)
wc file.txt                     # Lines, words, characters
wc -l file.txt                  # Line count
wc -w file.txt                  # Word count
wc -c file.txt                  # Character count

# TR (translate/delete characters)
tr 'a-z' 'A-Z' < file.txt       # Lowercase to uppercase
tr -d '0-9' < file.txt          # Delete digits

# DIFF (compare files)
diff file1.txt file2.txt
diff -u file1.txt file2.txt     # Unified format
diff -r dir1/ dir2/             # Recursive directory compare
```

## Process Management

```bash
# View processes
ps                              # Current shell processes
ps aux                          # All processes
ps -ef                          # Full format
ps -u username                  # User's processes
ps aux | grep process_name      # Find specific process

# Top (interactive process viewer)
top                             # Real-time process view
htop                            # Enhanced top (if installed)
top -u username                 # User's processes

# Kill processes
kill PID                        # Terminate process
kill -9 PID                     # Force kill
killall process_name            # Kill by name
pkill process_name              # Kill by name (pattern)
pkill -u username               # Kill user's processes

# Background/Foreground
command &                       # Run in background
Ctrl+Z                          # Suspend current process
bg                              # Resume in background
fg                              # Bring to foreground
jobs                            # List background jobs

# Process priority
nice -n 10 command              # Run with lower priority
renice -n 5 -p PID              # Change priority
```

## User Management

```bash
# User information
whoami                          # Current user
who                             # Logged in users
w                               # Who and what they're doing
id                              # User and group IDs
id username                     # Specific user info

# User management (requires sudo)
sudo useradd username           # Add user
sudo useradd -m username        # Add user with home directory
sudo userdel username           # Delete user
sudo userdel -r username        # Delete user and home directory
sudo usermod -aG group username # Add user to group
sudo passwd username            # Change user password
sudo chsh -s /bin/bash username # Change shell

# Group management
groups                          # Show user's groups
groups username                 # Show user's groups
sudo groupadd groupname         # Create group
sudo groupdel groupname         # Delete group
sudo gpasswd -a user group      # Add user to group
sudo gpasswd -d user group      # Remove user from group

# Switch users
su - username                   # Switch user
sudo -i                         # Root shell
sudo -u username command        # Run command as user
sudo -s                         # Shell as root
```

## Permissions

```bash
# View permissions
ls -l file.txt
stat file.txt                   # Detailed file info

# Change permissions (numeric)
chmod 755 file.txt              # rwxr-xr-x
chmod 644 file.txt              # rw-r--r--
chmod 600 file.txt              # rw-------
chmod 777 file.txt              # rwxrwxrwx (dangerous!)

# Change permissions (symbolic)
chmod u+x file.txt              # Add execute for user
chmod g-w file.txt              # Remove write for group
chmod o+r file.txt              # Add read for others
chmod a+x file.txt              # Add execute for all

# Recursive permissions
chmod -R 755 directory/

# Change ownership
chown user:group file.txt
chown user file.txt
chown -R user:group directory/

# Special permissions
chmod +s file                   # SUID/SGID
chmod +t directory              # Sticky bit
chmod 4755 file                 # SUID with 755

# ACLs (Access Control Lists)
getfacl file.txt                # View ACL
setfacl -m u:user:rw file.txt   # Set user ACL
setfacl -m g:group:r file.txt   # Set group ACL
setfacl -R -m u:user:rw dir/    # Recursive ACL
setfacl -x u:user file.txt      # Remove ACL
```

## Networking

```bash
# Network configuration
ifconfig                        # Network interfaces (deprecated)
ip addr show                    # Show IP addresses
ip link show                    # Show network interfaces
ip route show                   # Show routing table

# Network connectivity
ping host                       # Test connectivity
ping -c 4 host                  # Ping 4 times
traceroute host                 # Trace route to host
mtr host                        # Combined ping and traceroute

# DNS
nslookup domain.com             # DNS lookup
dig domain.com                  # DNS lookup (detailed)
dig +short domain.com           # Simple DNS lookup
host domain.com                 # DNS lookup

# Network connections
netstat -tuln                   # Listening ports
netstat -tunap                  # All connections
ss -tuln                        # Socket statistics (newer)
lsof -i :80                     # Process using port 80
lsof -i tcp                     # TCP connections

# Download files
wget URL                        # Download file
wget -O filename URL            # Save as filename
curl URL                        # Display content
curl -O URL                     # Download file
curl -L URL                     # Follow redirects

# SSH
ssh user@host                   # Connect to remote host
ssh -p port user@host           # Custom port
ssh -i keyfile user@host        # Use key file
scp file.txt user@host:/path/   # Copy file to remote
scp user@host:/path/file.txt .  # Copy file from remote
scp -r dir/ user@host:/path/    # Copy directory

# Network scanning (if installed)
nmap -sn 192.168.1.0/24         # Ping scan
nmap -sS 192.168.1.1            # SYN scan
nmap -sV 192.168.1.1            # Version detection
nmap -p- 192.168.1.1            # All ports
```

## System Information

```bash
# System info
uname -a                        # Kernel and system info
hostname                        # System hostname
hostnamectl                     # Detailed hostname info
uptime                          # System uptime
date                            # Current date/time

# Hardware info
lscpu                           # CPU information
lsmem                           # Memory information
lsblk                           # Block devices
lsusb                           # USB devices
lspci                           # PCI devices
dmidecode                       # Hardware information

# Disk usage
df -h                           # Disk space usage
df -i                           # Inode usage
du -h directory/                # Directory size
du -sh directory/               # Directory size (summary)
du -h --max-depth=1             # Subdirectory sizes

# Memory usage
free -h                         # Memory usage
vmstat                          # Virtual memory statistics
cat /proc/meminfo               # Detailed memory info

# Logs
journalctl                      # Systemd journal
journalctl -u service           # Service logs
journalctl -f                   # Follow logs
tail -f /var/log/syslog         # Follow syslog
dmesg                           # Kernel ring buffer
last                            # Last logged in users
lastlog                         # Last login per user
```

## Package Management

### Debian/Ubuntu (APT)

```bash
# Update package lists
sudo apt update

# Upgrade packages
sudo apt upgrade
sudo apt full-upgrade

# Install package
sudo apt install package_name

# Remove package
sudo apt remove package_name
sudo apt purge package_name     # Remove with config

# Search packages
apt search keyword
apt-cache search keyword

# Package information
apt show package_name

# List installed packages
apt list --installed
dpkg -l

# Clean package cache
sudo apt autoclean
sudo apt autoremove
```

### Red Hat/CentOS (YUM/DNF)

```bash
# Update packages
sudo yum update
sudo dnf update

# Install package
sudo yum install package_name
sudo dnf install package_name

# Remove package
sudo yum remove package_name

# Search packages
yum search keyword

# Package information
yum info package_name

# List installed packages
yum list installed
rpm -qa
```

## Archiving and Compression

```bash
# TAR (archive)
tar -cvf archive.tar files/     # Create archive
tar -xvf archive.tar            # Extract archive
tar -tvf archive.tar            # List contents

# TAR with compression
tar -czvf archive.tar.gz files/ # Create gzip archive
tar -xzvf archive.tar.gz        # Extract gzip archive
tar -cjvf archive.tar.bz2 files/ # Create bzip2 archive
tar -xjvf archive.tar.bz2       # Extract bzip2 archive

# GZIP
gzip file.txt                   # Compress file
gunzip file.txt.gz              # Decompress file

# BZIP2
bzip2 file.txt                  # Compress file
bunzip2 file.txt.bz2            # Decompress file

# ZIP
zip archive.zip files/          # Create zip archive
zip -r archive.zip directory/   # Recursive zip
unzip archive.zip               # Extract zip archive
unzip -l archive.zip            # List zip contents

# 7Z
7z a archive.7z files/          # Create 7z archive
7z x archive.7z                 # Extract 7z archive
```

## Security Commands

```bash
# Firewall (UFW)
sudo ufw status                 # Check firewall status
sudo ufw enable                 # Enable firewall
sudo ufw disable                # Disable firewall
sudo ufw allow 22/tcp           # Allow SSH
sudo ufw deny 80/tcp            # Deny HTTP
sudo ufw delete allow 22/tcp    # Remove rule

# Firewall (iptables)
sudo iptables -L                # List rules
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# AppArmor
sudo aa-status                  # AppArmor status
sudo aa-enforce /path/to/profile
sudo aa-complain /path/to/profile

# SELinux
getenforce                      # SELinux status
setenforce 0                    # Set permissive
setenforce 1                    # Set enforcing
sestatus                        # Detailed status

# File integrity
md5sum file.txt                 # MD5 checksum
sha256sum file.txt              # SHA256 checksum
sha512sum file.txt              # SHA512 checksum

# GPG encryption
gpg --gen-key                   # Generate key pair
gpg --encrypt file.txt          # Encrypt file
gpg --decrypt file.txt.gpg      # Decrypt file
gpg --list-keys                 # List public keys

# Secure delete
shred -vfz -n 10 file.txt       # Secure delete file
srm file.txt                    # Secure remove (if installed)

# Password management
passwd                          # Change password
sudo passwd username            # Change user password
passwd -l username              # Lock user account
passwd -u username              # Unlock user account

# Last login attempts
last                            # Successful logins
lastb                           # Failed logins (requires root)

# System audit
sudo ausearch -m LOGIN          # Search audit logs
sudo aureport                   # Audit report
```

## Essential Shortcuts

```bash
# Command line editing
Ctrl+A      # Beginning of line
Ctrl+E      # End of line
Ctrl+U      # Clear line before cursor
Ctrl+K      # Clear line after cursor
Ctrl+W      # Delete word before cursor
Ctrl+L      # Clear screen
Ctrl+R      # Search command history
Ctrl+C      # Cancel current command
Ctrl+Z      # Suspend current process
Ctrl+D      # Exit shell/EOF

# Command history
history                         # Show command history
!n                              # Execute command number n
!!                              # Execute last command
!string                         # Execute last command starting with string
history | grep keyword          # Search history
```

## Piping and Redirection

```bash
# Redirection
command > file.txt              # Redirect stdout to file (overwrite)
command >> file.txt             # Redirect stdout to file (append)
command 2> error.txt            # Redirect stderr to file
command &> all.txt              # Redirect both stdout and stderr
command < input.txt             # Read input from file

# Pipes
command1 | command2             # Pipe output to input
command | tee file.txt          # Display and save output
command | xargs                 # Convert stdin to arguments

# Multiple commands
command1 ; command2             # Run sequentially
command1 && command2            # Run command2 if command1 succeeds
command1 || command2            # Run command2 if command1 fails
command &                       # Run in background
```

## Resources

- [Linux Command Line Basics](https://ubuntu.com/tutorials/command-line-for-beginners)
- [The Linux Documentation Project](https://www.tldp.org/)
- [Linux Journey](https://linuxjourney.com/)
- [ExplainShell](https://explainshell.com/)

