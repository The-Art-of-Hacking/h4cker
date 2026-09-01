# Netcat (`nc`) Cheat Sheet

Netcat is a lightweight command-line tool for reading and writing data over TCP or UDP connections. It is useful for authorized connectivity troubleshooting, service validation, simple data transfer in trusted networks, and protocol testing.

> **Use only on systems and networks you own or are explicitly authorized to test.**
>
> Traditional `nc` traffic is generally plaintext and unauthenticated. Prefer SSH, TLS-enabled `ncat`, or another authenticated transport for sensitive data.

## Contents

- [Implementation differences](#implementation-differences)
- [Quick reference](#quick-reference)
- [TCP and UDP connectivity](#tcp-and-udp-connectivity)
- [Listening for connections](#listening-for-connections)
- [Authorized port checks](#authorized-port-checks)
- [Protocol and banner testing](#protocol-and-banner-testing)
- [Trusted file transfers](#trusted-file-transfers)
- [Ncat for TLS and proxies](#ncat-for-tls-and-proxies)
- [Troubleshooting](#troubleshooting)
- [Security guidance](#security-guidance)

## Implementation differences

`nc` is not fully standardized. Check the local manual page before relying on a flag:

```bash
nc -h
man nc
```

Common implementations:

| Implementation | Typical platform | Notes |
|---|---|---|
| OpenBSD `nc` | Modern Linux distributions, macOS, BSD | Common and security-conscious implementation; listener syntax is typically `nc -l PORT` |
| Traditional Netcat | Older Linux systems | May support options absent from OpenBSD `nc`; behavior varies |
| BusyBox `nc` | Embedded systems and containers | Often has a reduced feature set |
| Nmap `ncat` | Installed with Nmap or separately | Adds TLS, proxy support, ACLs, broker mode, and other features |

Avoid assuming that `-e`, `-c`, `-p`, `-q`, or `-k` behaves the same everywhere.

## Quick reference

```bash
# TCP connection
nc example.com 80

# TCP connection with a 5-second connection/read timeout
nc -w 5 example.com 443

# Skip DNS resolution and use a numeric address
nc -n 192.0.2.10 443

# UDP connection
nc -u 198.51.100.53 53

# Listen on TCP port 9000 (OpenBSD nc syntax)
nc -l 9000

# Verbose listener
nc -lv 9000

# Check a TCP port without sending application data
nc -zv -w 3 example.com 443
```

## TCP and UDP connectivity

### Test a TCP service

```bash
# Connect interactively
nc -v example.com 80

# Connect using a numeric address and timeout
nc -nv -w 5 192.0.2.10 22

# Send one line of data to a service
printf 'hello\n' | nc -w 3 example.com 12345
```

### Test a UDP service

UDP is connectionless, so a successful command does not always prove that a remote application received or processed the datagram.

```bash
# Send a DNS-like test payload to an authorized UDP listener
printf 'test\n' | nc -u -w 3 198.51.100.53 9999

# Listen for UDP datagrams
nc -ul 9999
```

### Specify a source port

Some implementations support `-p` for an explicit local source port in client mode:

```bash
nc -p 40000 example.com 443
```

Verify local behavior with `man nc`; source-port binding may require elevated privileges for ports below 1024.

## Listening for connections

### Basic TCP listener

```bash
# OpenBSD nc: listen on TCP port 9000
nc -lv 9000
```

### Keep a listener available

Some implementations provide `-k` to accept additional connections:

```bash
nc -lkv 9000
```

If `-k` is unavailable, use a controlled loop for a lab or temporary diagnostic endpoint:

```bash
while true; do
  nc -lv 9000
done
```

Do not expose unauthenticated listeners to untrusted networks.

### Receive a one-way message

Receiver:

```bash
nc -lv 9000 > received-message.txt
```

Sender:

```bash
printf 'Maintenance test completed.\n' | nc -w 3 192.0.2.20 9000
```

## Authorized port checks

Use `-z` for zero-I/O connection checks. This is appropriate for inventory validation and authorized troubleshooting, not broad or unauthorized scanning.

```bash
# Check one TCP port
nc -zv -w 3 example.com 443

# Check a limited list of expected service ports
nc -zv -w 3 example.com 22 80 443

# Check a small, authorized port range
nc -zv -w 1 192.0.2.10 8000-8010
```

For UDP:

```bash
nc -zuv -w 3 198.51.100.53 53
```

Interpret UDP results carefully. Many UDP services do not reply to unexpected data, and filtering can make open, closed, and filtered states difficult to distinguish.

## Protocol and banner testing

### HTTP

Use HTTP/1.1 with a `Host` header:

```bash
printf 'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
  | nc -w 5 example.com 80
```

For a plain HTTP service on an IP address:

```bash
printf 'GET /health HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n' \
  | nc -w 5 192.0.2.10 8080
```

For HTTPS, use `curl` or `openssl s_client`; ordinary `nc` does not negotiate TLS.

### SMTP greeting

```bash
printf 'EHLO client.example.com\r\nQUIT\r\n' \
  | nc -w 5 mail.example.com 25
```

### SSH banner

```bash
nc -v -w 5 ssh.example.com 22
```

### Redis health check

Only for an authorized instance:

```bash
printf 'PING\r\n' | nc -w 3 127.0.0.1 6379
```

Expected response:

```text
+PONG
```

### Generic line-oriented protocol test

```bash
printf 'STATUS\r\n' | nc -w 3 192.0.2.30 9000
```

## Trusted file transfers

Plain Netcat transfers have no encryption, authentication, resumption, or integrity checking. Use them only in a trusted, controlled environment. Prefer `scp`, `sftp`, `rsync -e ssh`, or a TLS-enabled alternative for real operational transfers.

### Transfer one file

On the receiving system:

```bash
nc -lv 9000 > received.tar.gz
```

On the sending system:

```bash
nc -w 10 192.0.2.20 9000 < archive.tar.gz
```

### Verify integrity

Before transfer:

```bash
sha256sum archive.tar.gz
```

After transfer:

```bash
sha256sum received.tar.gz
```

Compare the two digests through an authenticated channel.

### Transfer a directory archive

Receiver:

```bash
nc -lv 9000 > project.tar.gz
```

Sender:

```bash
tar -czf - ./project | nc -w 10 192.0.2.20 9000
```

Extract only after validating the received archive:

```bash
tar -tzf project.tar.gz
tar -xzf project.tar.gz
```

## Ncat for TLS and proxies

[`ncat`](https://nmap.org/ncat/) is the Nmap Project implementation of Netcat. It provides TLS support, proxy support, access controls, and broker mode.

### TLS client

```bash
ncat --ssl example.com 443
```

### TLS client with certificate verification

```bash
ncat --ssl --ssl-verify example.com 443
```

For application protocols such as HTTPS, use a protocol-aware tool like `curl` whenever possible.

### TLS listener

Generate and manage certificates according to your organization’s PKI practices. For a temporary lab certificate:

```bash
ncat -l 9443 --ssl --ssl-cert server.pem --ssl-key server-key.pem
```

### Connect through a proxy

```bash
# HTTP CONNECT proxy
ncat --proxy proxy.example.com:8080 --proxy-type http example.com 443

# SOCKS5 proxy
ncat --proxy proxy.example.com:1080 --proxy-type socks5 example.com 443
```

### Restrict a listener

```bash
ncat -l 9000 --allow 192.0.2.50
```

Use network firewall rules as the primary control; Ncat allow/deny rules are an additional safeguard.

## Troubleshooting

### Common checks

```bash
# Confirm the local listener exists
ss -lntup | grep 9000

# Alternative on systems with net-tools
netstat -lntup | grep 9000

# Test local connectivity
nc -zv 127.0.0.1 9000

# Check routing to a remote host
ip route get 192.0.2.20

# Observe packets during an authorized test
sudo tcpdump -ni any host 192.0.2.20 and port 9000
```

### Frequent issues

| Symptom | Likely causes | Useful checks |
|---|---|---|
| `Connection refused` | No service is listening, or a local firewall actively rejects the connection | Check the listener with `ss`; validate host firewall rules |
| Connection times out | Network filtering, routing issue, wrong address, or silent packet drop | Use `ip route get`; capture traffic with `tcpdump`; confirm ACLs and security groups |
| Listener exits after one client | The local `nc` implementation accepts a single connection by default | Check for `-k`; otherwise use an intentional loop only in a controlled environment |
| File transfer hangs | One side did not close the connection, timeout is too short, or firewall state expired | Use `-w`; verify both processes and intermediate firewalls |
| UDP test is inconclusive | UDP has no session establishment and services may not respond | Use an application-aware client or capture packets to confirm delivery |

## Security guidance

- Treat all ordinary `nc` traffic as plaintext. Do not transmit credentials, secrets, personal data, or production backups over it.
- Bind temporary listeners to a management interface or restrict reachability using host and network firewalls.
- Use high, non-conflicting ports and remove diagnostic listeners immediately after testing.
- Prefer protocol-aware tools when available: `curl` for HTTP(S), `openssl s_client` for TLS, `dig` for DNS, and SSH-based tools for remote administration and file transfer.
- Prefer `ncat --ssl --ssl-verify` or SSH-based transports where confidentiality and endpoint authentication matter.
- Record scope and authorization for port validation or network testing activities.
- Avoid using Netcat to execute remote commands, establish shell access, bypass security controls, or maintain persistence.

## References

- [OpenBSD `nc(1)` manual](https://man.openbsd.org/nc)
- [Ncat User Guide](https://nmap.org/ncat/guide/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
