# TLS/SSL Complete Practical Guide

## Table of Contents
- [Introduction to TLS/SSL](#introduction-to-tlsssl)
- [TLS Protocol Overview](#tls-protocol-overview)
- [Certificate Configuration](#certificate-configuration)
- [Cipher Suite Selection](#cipher-suite-selection)
- [Modern TLS Configuration](#modern-tls-configuration)
- [Testing and Validation](#testing-and-validation)
- [Performance Optimization](#performance-optimization)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Introduction to TLS/SSL

Transport Layer Security (TLS) and its predecessor Secure Sockets Layer (SSL) are cryptographic protocols designed to provide secure communications over a computer network.

### Protocol Evolution

| Protocol | Year | Status | Notes |
|----------|------|--------|-------|
| SSL 1.0 | 1994 | Never released | Security flaws |
| SSL 2.0 | 1995 | **Deprecated** | DROWN, other vulnerabilities |
| SSL 3.0 | 1996 | **Deprecated** | POODLE vulnerability |
| TLS 1.0 | 1999 | **Deprecated** | BEAST, weak ciphers |
| TLS 1.1 | 2006 | **Deprecated** | Insufficient security |
| TLS 1.2 | 2008 | **Current minimum** | Widely supported |
| TLS 1.3 | 2018 | **Recommended** | Improved security & performance |

⚠️ **Security Notice**: Only use TLS 1.2+ in production. TLS 1.3 is strongly recommended.

### TLS 1.3 Improvements

- Faster handshake (1-RTT instead of 2-RTT)
- 0-RTT mode for resumed connections
- Simplified cipher suite negotiation
- Forward secrecy required
- Removed insecure algorithms (RSA key exchange, CBC mode, etc.)
- Encrypted handshake messages

## TLS Protocol Overview

### TLS 1.2 Handshake

```
Client                                                Server

ClientHello                   -------->
                                                ServerHello
                                               Certificate*
                                         ServerKeyExchange*
                                        CertificateRequest*
                              <--------      ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished                      -------->
                                         [ChangeCipherSpec]
                              <--------             Finished
Application Data              <------->     Application Data

* Optional or situation-dependent messages
```

### TLS 1.3 Handshake

```
Client                                                Server

ClientHello
+ key_share                   -------->
                                                ServerHello
                                               + key_share
                                     {EncryptedExtensions}
                                     {CertificateRequest*}
                                            {Certificate*}
                                      {CertificateVerify*}
                                                {Finished}
                              <--------     [Application Data]
{Certificate*}
{CertificateVerify*}
{Finished}                    -------->
[Application Data]            <------->     [Application Data]

{} = encrypted, [] = optional, * = situation-dependent
```

### Key Exchange Methods

#### RSA Key Exchange (TLS 1.2 only, deprecated)

```
⚠️ DEPRECATED: No forward secrecy
- Server sends RSA public key
- Client encrypts pre-master secret with server's public key
- Server decrypts with private key
```

#### Diffie-Hellman Ephemeral (DHE)

```
✓ Provides forward secrecy
- Generate ephemeral key pairs
- Exchange public values
- Compute shared secret
- Discard ephemeral keys after session
```

#### Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

```
✓ RECOMMENDED: Forward secrecy + better performance
- Use elliptic curve operations
- Smaller keys, faster computation
- Preferred cipher suites in TLS 1.2+
- Required in TLS 1.3
```

## Certificate Configuration

### Obtaining Certificates

#### Let's Encrypt (Free, Automated)

```bash
# Install Certbot
sudo apt update
sudo apt install certbot python3-certbot-apache

# Obtain certificate (Apache)
sudo certbot --apache -d example.com -d www.example.com

# Obtain certificate (Nginx)
sudo apt install python3-certbot-nginx
sudo certbot --nginx -d example.com -d www.example.com

# Manual certificate (DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns \
  -d example.com -d *.example.com

# Wildcard certificate
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.example.com" -d example.com

# Automatic renewal (cron)
sudo certbot renew --dry-run
echo "0 0,12 * * * root certbot renew --quiet" | \
  sudo tee -a /etc/crontab > /dev/null
```

#### Commercial CA

```bash
# Generate private key
openssl genpkey -algorithm RSA -pkcs8 -out domain.key

# Generate CSR
openssl req -new -key domain.key -out domain.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

# Submit CSR to CA and receive certificate
# Install certificate as shown below
```

### Certificate Installation

#### Apache Configuration

```apache
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    
    # Enable SSL/TLS
    SSLEngine on
    
    # Certificate files
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt
    
    # Modern TLS configuration
    SSLProtocol -all +TLSv1.3 +TLSv1.2
    SSLCipherSuite TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    
    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
    
    # Session tickets
    SSLSessionTickets on
    
    DocumentRoot /var/www/html
    
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/ssl_error.log
    CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

#### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;
    
    # Certificate files
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    ssl_trusted_certificate /etc/ssl/certs/intermediate.crt;
    
    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    # Session settings
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Diffie-Hellman parameter
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
    
    root /var/www/html;
    index index.html index.php;
    
    location / {
        try_files $uri $uri/ =404;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
```

#### Generate DH Parameters

```bash
# Generate strong DH parameters (takes time)
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
# Or for higher security (slower)
openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
```

## Cipher Suite Selection

### Modern Cipher Suite (Recommended)

**For TLS 1.3:**
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

**For TLS 1.2:**
```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
```

### Cipher Suite Components

```
ECDHE-RSA-AES128-GCM-SHA256
  │     │    │     │    │
  │     │    │     │    └─── Hash algorithm (HMAC)
  │     │    │     └──────── Authenticated encryption mode
  │     │    └────────────── Symmetric cipher & key size
  │     └─────────────────── Authentication algorithm
  └───────────────────────── Key exchange algorithm
```

### Weak Ciphers to Avoid

⚠️ **Never use:**
- NULL ciphers (no encryption)
- EXPORT ciphers (weak 40/56-bit)
- DES, 3DES (broken/weak)
- RC4 (broken)
- MD5 (collision attacks)
- Anonymous DH (no authentication)
- CBC mode with TLS 1.0/1.1 (BEAST attack)

```bash
# Test for weak ciphers
nmap --script ssl-enum-ciphers -p 443 example.com
```

## Modern TLS Configuration

### Mozilla SSL Configuration Generator

Use the [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) for up-to-date configurations.

### Configuration Profiles

#### Modern (TLS 1.3 only)

**Best security, limited compatibility**

```
Protocols: TLSv1.3
Cipher Suites: TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Compatible with: Firefox 63+, Chrome 70+, Edge 75+, Safari 12.1+
```

#### Intermediate (TLS 1.2+)

**Recommended for most websites**

```
Protocols: TLSv1.2, TLSv1.3
Cipher Suites: TLS 1.3 suites + ECDHE-based TLS 1.2 suites
Compatible with: Firefox 27+, Chrome 30+, IE 11+, Edge 12+, Safari 9+
```

#### Old (TLS 1.0+)

**Only if legacy compatibility required**

```
⚠️ Not recommended - use only if absolutely necessary
Protocols: TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
Compatible with: Very old clients
```

### Example Configurations

#### HAProxy

```
# Global settings
global
    ssl-default-bind-ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    
    ssl-default-server-ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

# Frontend
frontend https_frontend
    bind *:443 ssl crt /etc/ssl/certs/example.com.pem alpn h2,http/1.1
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    default_backend web_servers
```

#### Node.js (Express)

```javascript
const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

const options = {
    key: fs.readFileSync('/etc/ssl/private/example.com.key'),
    cert: fs.readFileSync('/etc/ssl/certs/example.com.crt'),
    ca: fs.readFileSync('/etc/ssl/certs/intermediate.crt'),
    
    // Modern TLS configuration
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384'
    ].join(':'),
    honorCipherOrder: false
};

app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    next();
});

https.createServer(options, app).listen(443);
```

## Testing and Validation

### SSL Labs Test

```bash
# Online testing (most comprehensive)
# Visit: https://www.ssllabs.com/ssltest/

# Aim for A+ rating
```

### Command-Line Tools

#### testssl.sh (Comprehensive)

```bash
# Install
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Run full test
./testssl.sh example.com

# Quick test
./testssl.sh --fast example.com

# Check specific issues
./testssl.sh --heartbleed --ccs-injection --ticketbleed example.com

# Test specific protocol
./testssl.sh --protocols example.com

# Test cipher suites
./testssl.sh --ciphers example.com
```

#### OpenSSL s_client

```bash
# Test TLS 1.3 connection
openssl s_client -connect example.com:443 -tls1_3

# Test TLS 1.2 connection
openssl s_client -connect example.com:443 -tls1_2

# Test specific cipher
openssl s_client -connect example.com:443 \
  -cipher ECDHE-RSA-AES128-GCM-SHA256

# View certificate chain
openssl s_client -connect example.com:443 -showcerts

# Test OCSP stapling
openssl s_client -connect example.com:443 -status

# Test SNI (Server Name Indication)
openssl s_client -connect example.com:443 -servername example.com
```

#### nmap

```bash
# Enumerate SSL/TLS ciphers
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for SSL vulnerabilities
nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection \
  -p 443 example.com

# SSL/TLS certificate info
nmap --script ssl-cert -p 443 example.com
```

#### sslscan

```bash
# Install
sudo apt install sslscan

# Scan target
sslscan example.com

# Show certificate details
sslscan --show-certificate example.com

# Test specific TLS version
sslscan --tls12 example.com
```

## Performance Optimization

### Session Resumption

#### Session IDs (TLS 1.2)

```nginx
# Nginx
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
```

```apache
# Apache
SSLSessionCache shmcb:/var/cache/apache2/ssl_scache(512000)
SSLSessionCacheTimeout 300
```

#### Session Tickets (TLS 1.2+)

```nginx
# Nginx
ssl_session_tickets on;
ssl_session_ticket_key /etc/ssl/ticket.key;
```

⚠️ **Note**: Session tickets can compromise forward secrecy if not rotated regularly.

### HTTP/2 and HTTP/3

#### HTTP/2 (over TLS 1.2+)

```nginx
# Nginx
listen 443 ssl http2;
```

```apache
# Apache (requires mod_http2)
Protocols h2 http/1.1
```

#### HTTP/3 (QUIC)

```nginx
# Nginx (with quic module)
listen 443 quic reuseport;
listen 443 ssl http2;

ssl_early_data on;
ssl_protocols TLSv1.3;

add_header Alt-Svc 'h3=":443"; ma=86400';
```

### OCSP Stapling

Reduces latency by having server fetch OCSP responses.

```nginx
# Nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

```apache
# Apache
SSLUseStapling on
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off
```

### Certificate Compression

```nginx
# TLS 1.3 certificate compression (experimental)
ssl_conf_command Options KTLS;
```

## Security Best Practices

### HSTS (HTTP Strict Transport Security)

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**HSTS Preload**: Submit to https://hstspreload.org/

### Security Headers

```nginx
# Prevent clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS Protection
add_header X-XSS-Protection "1; mode=block" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions Policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Certificate Pinning (Advanced)

```nginx
# HTTP Public Key Pinning (DEPRECATED - use Certificate Transparency instead)
# add_header Public-Key-Pins 'pin-sha256="base64=="; max-age=2592000; includeSubDomains';
```

**Note**: HPKP is deprecated. Use Certificate Transparency Logs instead.

### Perfect Forward Secrecy

Ensure only ephemeral key exchange:

```
✓ ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
✓ DHE (Diffie-Hellman Ephemeral)
✗ RSA key exchange (no forward secrecy)
```

### Regular Updates

```bash
# Update OpenSSL
sudo apt update && sudo apt upgrade openssl

# Check OpenSSL version
openssl version -a

# Update web server
sudo apt upgrade apache2  # or nginx
```

## Troubleshooting

### Common Issues

#### Certificate Validation Errors

```bash
# Check certificate validity
openssl x509 -in cert.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca-bundle.crt cert.pem

# Check certificate matches private key
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
```

#### Handshake Failures

```bash
# Debug TLS handshake
openssl s_client -connect example.com:443 -state -debug

# Test specific protocol version
openssl s_client -connect example.com:443 -tls1_2 -state

# Verbose output
curl -vv https://example.com
```

#### Mixed Content Warnings

```bash
# Find mixed content
grep -r "http://" /var/www/html/

# Use relative URLs or HTTPS
sed -i 's|http://example.com|https://example.com|g' *.html
```

#### Performance Issues

```bash
# Check session resumption
openssl s_client -connect example.com:443 -reconnect | grep "Session-ID"

# Monitor SSL/TLS performance
ab -n 1000 -c 10 https://example.com/

# Check OCSP stapling
openssl s_client -connect example.com:443 -status | grep "OCSP"
```

### Debugging Commands

```bash
# View server cipher preferences
openssl s_client -connect example.com:443 -cipher 'ALL' 2>&1 | \
  grep "Cipher"

# Test specific cipher suite
openssl s_client -connect example.com:443 \
  -cipher ECDHE-RSA-AES128-GCM-SHA256 -tls1_2

# Check TLS 1.3 support
openssl s_client -connect example.com:443 -tls1_3 < /dev/null

# Capture TLS handshake with tcpdump
sudo tcpdump -i any -s 0 -w tls_capture.pcap 'port 443'

# Analyze with Wireshark
wireshark tls_capture.pcap
```

## Additional Resources

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [testssl.sh](https://testssl.sh/)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Cloudflare SSL/TLS Guide](https://www.cloudflare.com/learning/ssl/what-is-ssl/)

