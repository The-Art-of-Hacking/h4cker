# OpenSSL Quick Reference Cheat Sheet

## Key Generation

### RSA Keys
```bash
# Generate RSA private key (modern)
openssl genpkey -algorithm RSA -pkcs8 -out key.pem

# Generate with specific key size
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out key.pem

# Generate encrypted private key
openssl genpkey -algorithm RSA -pkcs8 -aes256 -out key.pem

# Legacy RSA generation
openssl genrsa -out key.pem 3072
openssl genrsa -aes256 -out key.pem 3072
```

### EC (Elliptic Curve) Keys
```bash
# List available curves
openssl ecparam -list_curves

# Generate EC private key (P-256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_key.pem

# Generate EC private key (P-384)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ec_key.pem

# Generate Ed25519 key (modern)
openssl genpkey -algorithm Ed25519 -out ed25519_key.pem
```

### View Keys
```bash
# View private key details
openssl pkey -in key.pem -text -noout

# View RSA key
openssl rsa -in key.pem -text -noout

# View EC key
openssl ec -in ec_key.pem -text -noout

# Extract public key
openssl pkey -in key.pem -pubout -out public.pem
```

## Certificate Signing Requests (CSR)

### Create CSR
```bash
# Interactive CSR
openssl req -new -key key.pem -out request.csr

# Non-interactive CSR
openssl req -new -key key.pem -out request.csr \
  -subj "/C=US/ST=State/L=City/O=Company/CN=example.com"

# CSR with SANs
openssl req -new -key key.pem -out request.csr \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

# Generate key and CSR in one command
openssl req -new -newkey rsa:3072 -nodes -keyout key.pem -out request.csr
```

### View & Verify CSR
```bash
# View CSR details
openssl req -text -noout -in request.csr

# Verify CSR signature
openssl req -verify -in request.csr -text -noout

# Extract public key from CSR
openssl req -in request.csr -noout -pubkey
```

## Certificates

### Self-Signed Certificates
```bash
# Create self-signed certificate
openssl req -new -x509 -days 365 -key key.pem -out cert.crt

# Generate key and self-signed cert in one command
openssl req -new -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout key.pem -out cert.crt

# Self-signed with SANs
openssl req -new -x509 -days 365 -key key.pem -out cert.crt \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
```

### View Certificates
```bash
# View certificate details
openssl x509 -text -noout -in cert.crt

# View specific fields
openssl x509 -subject -noout -in cert.crt
openssl x509 -issuer -noout -in cert.crt
openssl x509 -dates -noout -in cert.crt
openssl x509 -serial -noout -in cert.crt
openssl x509 -fingerprint -noout -in cert.crt

# View SANs
openssl x509 -text -noout -in cert.crt | grep -A 1 "Subject Alternative Name"
```

### Certificate Verification
```bash
# Verify certificate
openssl verify cert.crt

# Verify against CA
openssl verify -CAfile ca.crt cert.crt

# Verify certificate chain
openssl verify -CAfile ca.crt -untrusted intermediate.crt cert.crt

# Check if cert and key match
openssl x509 -noout -modulus -in cert.crt | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
# MD5 hashes should match
```

## Certificate Formats

### PEM ↔ DER
```bash
# PEM to DER
openssl x509 -outform der -in cert.pem -out cert.der

# DER to PEM
openssl x509 -inform der -in cert.der -outform pem -out cert.pem
```

### PKCS#12 (PFX)
```bash
# Create PKCS#12 file
openssl pkcs12 -export -out cert.p12 \
  -inkey key.pem -in cert.crt -certfile ca.crt

# View PKCS#12 contents
openssl pkcs12 -info -in cert.p12

# Extract certificate
openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem

# Extract private key
openssl pkcs12 -in cert.p12 -nocerts -nodes -out key.pem

# Extract CA certificates
openssl pkcs12 -in cert.p12 -cacerts -nokeys -out ca.pem
```

## TLS/SSL Testing

### Connect to Server
```bash
# Test HTTPS connection
openssl s_client -connect example.com:443

# Show certificate chain
openssl s_client -connect example.com:443 -showcerts

# Test specific protocol
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Test specific cipher
openssl s_client -connect example.com:443 -cipher ECDHE-RSA-AES256-GCM-SHA384

# SNI (Server Name Indication)
openssl s_client -connect example.com:443 -servername example.com

# OCSP stapling check
openssl s_client -connect example.com:443 -status
```

### Extract Server Certificate
```bash
# Get server certificate
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 > server_cert.pem

# Get full certificate chain
openssl s_client -connect example.com:443 -showcerts 2>/dev/null | \
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > chain.pem
```

## Hashing & Digests

### Message Digests
```bash
# Calculate hash
openssl dgst -sha256 file.txt

# Sign with hash
openssl dgst -sha256 -sign key.pem -out signature.bin file.txt

# Verify signature
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin file.txt

# Common algorithms
openssl dgst -md5 file.txt
openssl dgst -sha1 file.txt
openssl dgst -sha256 file.txt
openssl dgst -sha512 file.txt
```

### HMAC
```bash
# Calculate HMAC
openssl dgst -sha256 -hmac "secret_key" file.txt
```

## Symmetric Encryption

### Encrypt Files
```bash
# Encrypt with AES-256-CBC
openssl enc -aes-256-cbc -salt -in plain.txt -out encrypted.bin

# Encrypt with password from file
openssl enc -aes-256-cbc -salt -in plain.txt -out encrypted.bin -pass file:password.txt

# Encrypt with Base64 encoding
openssl enc -aes-256-cbc -salt -a -in plain.txt -out encrypted.b64
```

### Decrypt Files
```bash
# Decrypt
openssl enc -d -aes-256-cbc -in encrypted.bin -out plain.txt

# Decrypt with Base64
openssl enc -d -aes-256-cbc -a -in encrypted.b64 -out plain.txt
```

### Available Ciphers
```bash
# List all ciphers
openssl enc -ciphers

# Common ciphers
-aes-256-cbc      # AES 256-bit CBC mode
-aes-256-gcm      # AES 256-bit GCM mode
-chacha20-poly1305 # ChaCha20-Poly1305
```

## Random Data Generation

```bash
# Generate random bytes (binary)
openssl rand 16 > random.bin

# Generate random bytes (hex)
openssl rand -hex 16

# Generate random bytes (base64)
openssl rand -base64 16

# Generate random password
openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
```

## S/MIME Email Encryption

```bash
# Sign email
openssl smime -sign -in msg.txt -out signed.msg \
  -signer cert.pem -inkey key.pem

# Verify signed email
openssl smime -verify -in signed.msg -CAfile ca.crt

# Encrypt email
openssl smime -encrypt -in msg.txt -out encrypted.msg \
  -des3 recipient_cert.pem

# Decrypt email
openssl smime -decrypt -in encrypted.msg -recip cert.pem -inkey key.pem
```

## CRL (Certificate Revocation List)

```bash
# View CRL
openssl crl -in crl.pem -text -noout

# Convert CRL formats
openssl crl -in crl.pem -outform DER -out crl.der
openssl crl -inform DER -in crl.der -outform PEM -out crl.pem

# Verify certificate against CRL
openssl verify -crl_check -CRLfile crl.pem -CAfile ca.crt cert.crt
```

## OCSP (Online Certificate Status Protocol)

```bash
# Check certificate status
openssl ocsp -issuer ca.crt -cert cert.crt \
  -url http://ocsp.example.com -resp_text

# Verify OCSP response
openssl ocsp -issuer ca.crt -cert cert.crt \
  -url http://ocsp.example.com -CAfile ca.crt
```

## Benchmarking

```bash
# Benchmark algorithms
openssl speed

# Benchmark specific algorithm
openssl speed rsa
openssl speed aes-256-cbc
openssl speed sha256

# Benchmark for specific time
openssl speed -seconds 10 rsa
```

## Useful One-Liners

```bash
# Generate self-signed cert (one command)
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"

# Check certificate expiration
openssl x509 -enddate -noout -in cert.crt | cut -d= -f2

# Days until expiration
echo $(( ($(date -d "$(openssl x509 -enddate -noout -in cert.crt | \
  cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))

# Extract domain from certificate
openssl x509 -noout -subject -in cert.crt | sed -n 's/.*CN=\(.*\)/\1/p'

# Check if certificate is valid
openssl x509 -checkend 0 -noout -in cert.crt && echo "Valid" || echo "Expired"

# Generate CSR from existing certificate
openssl x509 -x509toreq -in cert.crt -signkey key.pem -out request.csr
```

## Configuration File

### OpenSSL Config Template
```ini
# openssl.cnf
[req]
default_bits = 3072
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
CN=example.com

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 192.168.1.1
```

### Use Config File
```bash
# Generate CSR with config
openssl req -new -key key.pem -out request.csr -config openssl.cnf

# Generate certificate with config
openssl req -new -x509 -days 365 -key key.pem -out cert.crt \
  -config openssl.cnf -extensions v3_req
```

## Troubleshooting

```bash
# Verbose output
openssl s_client -connect example.com:443 -showcerts -debug

# Check OpenSSL version
openssl version -a

# View supported ciphers
openssl ciphers -v

# Test if file is valid certificate
openssl x509 -in file.crt -text -noout 2>&1 | grep -q "Certificate:" && \
  echo "Valid" || echo "Invalid"

# Check file format
file cert.crt
```

## Common Options

| Option | Description |
|--------|-------------|
| `-in file` | Input file |
| `-out file` | Output file |
| `-text` | Print in text form |
| `-noout` | Don't output encoded version |
| `-nodes` | Don't encrypt private key |
| `-days n` | Number of days cert is valid |
| `-subj arg` | Set subject name |
| `-addext arg` | Add certificate extension |
| `-verify` | Verify signature |

## Quick Task Reference

| Task | Command |
|------|---------|
| Generate RSA key | `openssl genpkey -algorithm RSA -out key.pem` |
| Generate EC key | `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem` |
| Create CSR | `openssl req -new -key key.pem -out request.csr` |
| Self-signed cert | `openssl req -x509 -newkey rsa:3072 -nodes -days 365 -keyout key.pem -out cert.pem` |
| View certificate | `openssl x509 -text -noout -in cert.crt` |
| Verify certificate | `openssl verify -CAfile ca.crt cert.crt` |
| Test HTTPS | `openssl s_client -connect example.com:443` |
| PEM to DER | `openssl x509 -outform der -in cert.pem -out cert.der` |
| Create PKCS#12 | `openssl pkcs12 -export -out cert.p12 -inkey key.pem -in cert.crt` |
| Encrypt file | `openssl enc -aes-256-cbc -salt -in file.txt -out file.enc` |

## See Also
- `man openssl` - OpenSSL manual
- `openssl help` - List of commands
- [OpenSSL.org](https://www.openssl.org) - Official website
- [OpenSSL Cookbook](https://www.feistyduck.com/books/openssl-cookbook/)

