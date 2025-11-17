# Bash Scripting for Cybersecurity

Bash (Bourne Again Shell) is a powerful scripting language used extensively in Linux/Unix systems for automation and security tasks.

## 📋 Table of Contents
- [Basic Syntax](#basic-syntax)
- [Variables](#variables)
- [Input/Output](#inputoutput)
- [Conditionals](#conditionals)
- [Loops](#loops)
- [Functions](#functions)
- [File Operations](#file-operations)
- [String Manipulation](#string-manipulation)
- [Arrays](#arrays)
- [Security Scripts](#security-scripts)

## Basic Syntax

### Shebang and Execution

```bash
#!/bin/bash
# This is a comment

# Make script executable
chmod +x script.sh

# Run script
./script.sh
bash script.sh
```

### Basic Commands

```bash
# Print to console
echo "Hello World"
printf "Formatted: %s\n" "text"

# Exit status
exit 0  # Success
exit 1  # Error

# Check last exit status
echo $?
```

## Variables

```bash
# Variable assignment (no spaces around =)
name="hacker"
age=25

# Use variables
echo "Name: $name"
echo "Name: ${name}"

# Command substitution
current_date=$(date)
files=$(ls -l)

# Arithmetic
count=$((10 + 5))
count=$((count * 2))

# Read-only variables
readonly PI=3.14159

# Environment variables
export PATH="/usr/local/bin:$PATH"

# Special variables
$0  # Script name
$1  # First argument
$2  # Second argument
$#  # Number of arguments
$@  # All arguments as separate words
$*  # All arguments as single word
$$  # Process ID
$?  # Exit status of last command
```

## Input/Output

### Reading Input

```bash
# Read user input
read -p "Enter your name: " name
echo "Hello, $name"

# Read password (hidden)
read -s -p "Enter password: " password

# Read with timeout
read -t 5 -p "Enter quickly: " input

# Read into array
read -a array <<< "one two three"

# Read from file
while IFS= read -r line; do
    echo "$line"
done < file.txt
```

### Redirection

```bash
# Output redirection
echo "text" > file.txt      # Overwrite
echo "text" >> file.txt     # Append

# Error redirection
command 2> error.log        # Redirect stderr
command 2>&1                # Redirect stderr to stdout
command &> all.log          # Redirect both

# Input redirection
command < input.txt

# Here document
cat << EOF
Multi-line
text
EOF

# Here string
grep pattern <<< "search in this string"
```

## Conditionals

### If Statements

```bash
# Basic if
if [ condition ]; then
    echo "True"
fi

# If-else
if [ condition ]; then
    echo "True"
else
    echo "False"
fi

# If-elif-else
if [ condition1 ]; then
    echo "Condition 1"
elif [ condition2 ]; then
    echo "Condition 2"
else
    echo "Default"
fi

# One-liner
[ condition ] && echo "True" || echo "False"
```

### Test Operators

```bash
# File tests
-e file    # File exists
-f file    # Regular file
-d file    # Directory
-r file    # Readable
-w file    # Writable
-x file    # Executable
-s file    # File size > 0
-L file    # Symbolic link

# String tests
-z string  # Empty string
-n string  # Non-empty string
str1 = str2   # Equal
str1 != str2  # Not equal

# Numeric tests
$a -eq $b  # Equal
$a -ne $b  # Not equal
$a -gt $b  # Greater than
$a -lt $b  # Less than
$a -ge $b  # Greater or equal
$a -le $b  # Less or equal

# Logical operators
[ cond1 ] && [ cond2 ]  # AND
[ cond1 ] || [ cond2 ]  # OR
! [ cond ]              # NOT

# Examples
if [ -f /etc/passwd ]; then
    echo "File exists"
fi

if [ $age -gt 18 ]; then
    echo "Adult"
fi

if [ "$name" = "admin" ]; then
    echo "Welcome admin"
fi
```

### Case Statements

```bash
case $variable in
    pattern1)
        echo "Pattern 1"
        ;;
    pattern2|pattern3)
        echo "Pattern 2 or 3"
        ;;
    *)
        echo "Default"
        ;;
esac

# Example: Port identification
case $port in
    22)
        echo "SSH"
        ;;
    80)
        echo "HTTP"
        ;;
    443)
        echo "HTTPS"
        ;;
    *)
        echo "Unknown port"
        ;;
esac
```

## Loops

### For Loops

```bash
# C-style for loop
for ((i=0; i<10; i++)); do
    echo "Count: $i"
done

# Iterate over list
for item in one two three; do
    echo "$item"
done

# Iterate over files
for file in *.txt; do
    echo "Processing: $file"
done

# Iterate over command output
for user in $(cat /etc/passwd | cut -d: -f1); do
    echo "User: $user"
done

# Range
for i in {1..10}; do
    echo "$i"
done

# Range with step
for i in {0..100..10}; do
    echo "$i"
done
```

### While Loops

```bash
# Basic while loop
count=0
while [ $count -lt 10 ]; do
    echo "Count: $count"
    ((count++))
done

# Read file line by line
while IFS= read -r line; do
    echo "$line"
done < file.txt

# Infinite loop
while true; do
    echo "Running..."
    sleep 1
done

# Until loop (opposite of while)
until [ $count -ge 10 ]; do
    echo "$count"
    ((count++))
done
```

### Loop Control

```bash
# Break (exit loop)
for i in {1..10}; do
    if [ $i -eq 5 ]; then
        break
    fi
    echo "$i"
done

# Continue (skip iteration)
for i in {1..10}; do
    if [ $i -eq 5 ]; then
        continue
    fi
    echo "$i"
done
```

## Functions

```bash
# Basic function
function greet() {
    echo "Hello World"
}

# Alternative syntax
greet() {
    echo "Hello World"
}

# Call function
greet

# Function with arguments
greet_user() {
    echo "Hello, $1"
}
greet_user "Alice"

# Return values (0-255)
is_root() {
    if [ $EUID -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

if is_root; then
    echo "Running as root"
fi

# Return strings via echo
get_username() {
    echo "$USER"
}
username=$(get_username)

# Local variables
my_function() {
    local local_var="value"
    echo "$local_var"
}
```

## File Operations

```bash
# Check if file exists
if [ -f "file.txt" ]; then
    echo "File exists"
fi

# Create file
touch file.txt
echo "content" > file.txt

# Read file
content=$(cat file.txt)

# Read file line by line
while IFS= read -r line; do
    echo "$line"
done < file.txt

# Write to file
echo "new line" >> file.txt

# Copy file
cp source.txt dest.txt

# Move file
mv old.txt new.txt

# Delete file
rm file.txt

# Create directory
mkdir directory

# Remove directory
rmdir empty_directory
rm -rf directory

# Find files
find /path -name "*.txt"
find /path -type f -mtime -7

# Check file permissions
if [ -r file.txt ]; then
    echo "File is readable"
fi
```

## String Manipulation

```bash
# String length
string="Hello World"
echo ${#string}

# Substring
echo ${string:0:5}  # First 5 characters
echo ${string:6}    # From position 6 to end

# Replace
echo ${string/World/Universe}  # Replace first
echo ${string//o/0}            # Replace all

# Remove prefix/suffix
filename="file.txt.bak"
echo ${filename%.bak}     # Remove shortest suffix
echo ${filename%.*}       # Remove shortest from end
echo ${filename##*.}      # Get extension

# Convert case
echo ${string^^}          # Uppercase
echo ${string,,}          # Lowercase

# Concatenate
first="Hello"
second="World"
result="$first $second"

# Split string
IFS=',' read -ra parts <<< "one,two,three"
```

## Arrays

```bash
# Create array
arr=(one two three)
arr[0]="one"

# Access elements
echo ${arr[0]}          # First element
echo ${arr[@]}          # All elements
echo ${arr[*]}          # All elements (different quoting)

# Array length
echo ${#arr[@]}

# Add elements
arr+=(four)

# Loop through array
for item in "${arr[@]}"; do
    echo "$item"
done

# Array indices
for i in "${!arr[@]}"; do
    echo "$i: ${arr[$i]}"
done

# Associative arrays (bash 4+)
declare -A assoc_arr
assoc_arr[key1]="value1"
assoc_arr[key2]="value2"

echo ${assoc_arr[key1]}

# Loop through associative array
for key in "${!assoc_arr[@]}"; do
    echo "$key: ${assoc_arr[$key]}"
done
```

## Security Scripts

### Port Scanner

```bash
#!/bin/bash

# Simple port scanner
scan_port() {
    local host=$1
    local port=$2
    
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Port $port is open"
    fi
}

# Usage
read -p "Enter host: " target
for port in {1..1024}; do
    scan_port "$target" "$port"
done
```

### Log Monitor

```bash
#!/bin/bash

# Monitor logs for suspicious activity
LOGFILE="/var/log/auth.log"
KEYWORDS=("Failed password" "Invalid user" "authentication failure")

tail -f "$LOGFILE" | while read line; do
    for keyword in "${KEYWORDS[@]}"; do
        if echo "$line" | grep -q "$keyword"; then
            echo "[!] Alert: $line"
            # Send notification
        fi
    done
done
```

### Backup Script

```bash
#!/bin/bash

# Backup script
SOURCE="/home/user/data"
DEST="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_$DATE.tar.gz"

echo "Starting backup..."
tar -czf "$DEST/$BACKUP_FILE" "$SOURCE"

if [ $? -eq 0 ]; then
    echo "Backup completed: $BACKUP_FILE"
else
    echo "Backup failed!"
    exit 1
fi

# Remove old backups (keep last 7)
cd "$DEST"
ls -t backup_*.tar.gz | tail -n +8 | xargs rm -f
```

### System Information

```bash
#!/bin/bash

# System information gathering
echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(uname -s)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"

echo -e "\n=== Network Information ==="
ip addr show | grep "inet " | awk '{print $2}'

echo -e "\n=== Disk Usage ==="
df -h | grep "^/dev"

echo -e "\n=== Memory Usage ==="
free -h

echo -e "\n=== Top Processes ==="
ps aux --sort=-%mem | head -10
```

### User Enumeration

```bash
#!/bin/bash

# Enumerate users
echo "=== User Enumeration ==="

echo -e "\n[*] Current user:"
whoami

echo -e "\n[*] User privileges:"
id

echo -e "\n[*] Sudo privileges:"
sudo -l 2>/dev/null

echo -e "\n[*] All users:"
cat /etc/passwd | cut -d: -f1

echo -e "\n[*] Users with shell access:"
grep -v "nologin\|false" /etc/passwd | cut -d: -f1

echo -e "\n[*] Groups:"
cat /etc/group | cut -d: -f1
```

### Network Monitor

```bash
#!/bin/bash

# Network connection monitor
echo "Monitoring network connections..."

watch -n 2 '
echo "=== Active Connections ==="
netstat -tunap 2>/dev/null | grep ESTABLISHED

echo -e "\n=== Listening Ports ==="
netstat -tulnp 2>/dev/null | grep LISTEN
'
```

### File Integrity Checker

```bash
#!/bin/bash

# Simple file integrity checker
WATCH_DIR="/etc"
HASH_FILE="/tmp/file_hashes.txt"

# Create initial hashes
if [ ! -f "$HASH_FILE" ]; then
    echo "Creating initial hash database..."
    find "$WATCH_DIR" -type f -exec sha256sum {} \; > "$HASH_FILE"
    echo "Done. Run again to check for changes."
    exit 0
fi

# Check for changes
echo "Checking for file changes..."
find "$WATCH_DIR" -type f -exec sha256sum {} \; | while read hash file; do
    stored_hash=$(grep " $file$" "$HASH_FILE" | cut -d' ' -f1)
    
    if [ -z "$stored_hash" ]; then
        echo "[!] New file: $file"
    elif [ "$hash" != "$stored_hash" ]; then
        echo "[!] Modified: $file"
    fi
done
```

### Password Cracker

```bash
#!/bin/bash

# Simple password cracker for educational purposes
crack_password() {
    local hash=$1
    local wordlist=$2
    
    while IFS= read -r password; do
        computed_hash=$(echo -n "$password" | md5sum | cut -d' ' -f1)
        
        if [ "$computed_hash" = "$hash" ]; then
            echo "[+] Password found: $password"
            return 0
        fi
    done < "$wordlist"
    
    echo "[-] Password not found"
    return 1
}

# Usage
read -p "Enter MD5 hash: " hash
read -p "Enter wordlist path: " wordlist
crack_password "$hash" "$wordlist"
```

### Subdomain Enumeration

```bash
#!/bin/bash

# Subdomain enumeration
enumerate_subdomains() {
    local domain=$1
    local wordlist=$2
    
    while IFS= read -r subdomain; do
        result=$(host "$subdomain.$domain" 2>/dev/null)
        
        if echo "$result" | grep -q "has address"; then
            ip=$(echo "$result" | grep "has address" | awk '{print $4}')
            echo "[+] Found: $subdomain.$domain -> $ip"
        fi
    done < "$wordlist"
}

# Usage
read -p "Enter domain: " domain
read -p "Enter wordlist: " wordlist
enumerate_subdomains "$domain" "$wordlist"
```

## Best Practices

1. **Use meaningful variable names**
   ```bash
   # Bad
   x=10
   
   # Good
   port_number=10
   ```

2. **Quote variables**
   ```bash
   # Bad
   if [ $var = "value" ]; then
   
   # Good
   if [ "$var" = "value" ]; then
   ```

3. **Check command success**
   ```bash
   command
   if [ $? -eq 0 ]; then
       echo "Success"
   else
       echo "Failed"
       exit 1
   fi
   ```

4. **Use shellcheck**
   ```bash
   shellcheck script.sh
   ```

5. **Handle errors gracefully**
   ```bash
   set -e  # Exit on error
   set -u  # Error on undefined variable
   set -o pipefail  # Catch errors in pipes
   ```

6. **Use functions for reusability**
7. **Add comments and documentation**
8. **Validate input**
9. **Use absolute paths for security-critical scripts**
10. **Run with minimum necessary privileges**

## Resources

- [Bash Manual](https://www.gnu.org/software/bash/manual/)
- [ShellCheck](https://www.shellcheck.net/)
- [Bash Guide for Beginners](https://tldp.org/LDP/Bash-Beginners-Guide/html/)
- [Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/)

## Legal Notice

⚠️ **WARNING**: Only use these scripts on systems you own or have explicit permission to test. Unauthorized use is illegal.

---

**Pro Tip**: Always test your bash scripts in a safe environment before running them in production. Use `bash -x script.sh` to debug scripts by showing each command as it executes.

