# PKI Fundamentals: Complete Guide to Public Key Infrastructure

## Table of Contents
- [Introduction to PKI](#introduction-to-pki)
- [Core Components](#core-components)
- [Certificate Chains and Trust Models](#certificate-chains-and-trust-models)
- [Certificate Authority Operations](#certificate-authority-operations)
- [Certificate Lifecycle Management](#certificate-lifecycle-management)
- [PKI Deployment Models](#pki-deployment-models)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting Common Issues](#troubleshooting-common-issues)

## Introduction to PKI

Public Key Infrastructure (PKI) is a framework of policies, procedures, hardware, software, and people used to create, manage, distribute, use, store, and revoke digital certificates and manage public-key encryption.

### Why PKI Matters

- **Authentication**: Verify the identity of communicating parties
- **Confidentiality**: Ensure data is encrypted and protected
- **Integrity**: Detect tampering or alteration of data
- **Non-repudiation**: Prevent denial of actions performed

### PKI Use Cases

- **SSL/TLS**: Secure web communications (HTTPS)
- **Code Signing**: Verify software authenticity
- **Email Security**: S/MIME encrypted email
- **VPN**: Secure remote access
- **Document Signing**: PDF and digital document signing
- **IoT Security**: Device authentication and encryption

## Core Components

### 1. Certificate Authority (CA)

The trusted third party that issues digital certificates.

**Responsibilities:**
- Verify certificate applicant identities
- Issue and sign certificates
- Publish certificates and CRLs
- Maintain secure infrastructure

**Types of CAs:**
- **Root CA**: Top-level authority, self-signed certificate
- **Intermediate CA**: Subordinate to Root CA, issues end-entity certificates
- **Issuing CA**: Directly issues certificates to end users/devices

### 2. Registration Authority (RA)

Acts as intermediary between users and CA.

**Functions:**
- Verify certificate requests
- Approve or reject applications
- Initiate revocation requests
- Generate and manage keys (optional)

### 3. Digital Certificates

Electronic documents binding public keys to identities.

**Certificate Contents:**
```
Certificate:
    Version: V3 (0x2)
    Serial Number: 4096 (0x1000)
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=Example CA, O=Example Org, C=US
    Validity:
        Not Before: Jan 1 00:00:00 2025 GMT
        Not After : Jan 1 00:00:00 2027 GMT
    Subject: CN=example.com, O=Example Org, C=US
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
        RSA Public Key: (3072 bit)
            Modulus: ...
            Exponent: 65537 (0x10001)
    X509v3 Extensions:
        X509v3 Key Usage: critical
            Digital Signature, Key Encipherment
        X509v3 Extended Key Usage:
            TLS Web Server Authentication
        X509v3 Subject Alternative Name:
            DNS:example.com, DNS:www.example.com
```

### 4. Certificate Repository

Storage and distribution of certificates and CRLs.

**Common Implementations:**
- **LDAP Directory**: Centralized certificate storage
- **HTTP/HTTPS**: Web-based distribution
- **OCSP Responders**: Real-time certificate status
- **Certificate Transparency Logs**: Public audit logs

### 5. Certificate Revocation System

Mechanisms to invalidate certificates before expiration.

**Methods:**
- **CRL (Certificate Revocation List)**: Periodic list of revoked certificates
- **OCSP (Online Certificate Status Protocol)**: Real-time status queries
- **OCSP Stapling**: Server-provided certificate status
- **CRLSets**: Browser-specific revocation mechanisms

## Certificate Chains and Trust Models

### Certificate Chain Structure

```
┌─────────────────────────┐
│     Root CA             │
│  (Self-Signed)          │
│  Highly Protected       │
└───────────┬─────────────┘
            │ Signs
            ▼
┌─────────────────────────┐
│  Intermediate CA        │
│  (Signed by Root)       │
│  Operational Use        │
└───────────┬─────────────┘
            │ Signs
            ▼
┌─────────────────────────┐
│  End-Entity Certificate │
│  (Server, User, Device) │
│  Daily Operations       │
└─────────────────────────┘
```

### Chain Validation Process

```bash
# Verify certificate chain
openssl verify -CAfile root_ca.crt -untrusted intermediate_ca.crt server.crt

# View complete certificate chain
openssl s_client -connect example.com:443 -showcerts

# Extract and verify each certificate in chain
openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -text -noout
```

### Trust Models

#### 1. Hierarchical Trust Model

```
Root CA → Intermediate CA → End Entity
```

**Advantages:**
- Clear chain of trust
- Easy to understand and implement
- Scalable for large organizations

**Disadvantages:**
- Single point of failure at root
- Root compromise affects entire PKI

#### 2. Web of Trust (PGP Model)

```
User A ←→ User B
  ↕        ↕
User C ←→ User D
```

**Advantages:**
- Decentralized trust
- No single authority
- User-controlled trust decisions

**Disadvantages:**
- Complex trust calculations
- Difficult to scale
- No guaranteed trust path

#### 3. Bridge CA Model

```
Org A CA ←→ Bridge CA ←→ Org B CA
               ↕
           Org C CA
```

**Advantages:**
- Connects disparate PKIs
- Maintains organizational autonomy
- Facilitates cross-organization trust

**Disadvantages:**
- Complex trust relationships
- Requires coordination
- Bridge CA is critical component

#### 4. Hybrid Model

Combines elements of multiple models for flexibility.

## Certificate Authority Operations

### Setting Up a Private CA

#### Using OpenSSL

```bash
# Create directory structure
mkdir -p ca/{root-ca,intermediate-ca}/{private,certs,newcerts,crl}
cd ca/root-ca
touch index.txt
echo 1000 > serial

# Generate Root CA private key
openssl genpkey -algorithm RSA -pkcs8 -out private/root-ca.key \
  -aes256 -pass pass:SECURE_PASSWORD

# Create Root CA certificate
openssl req -new -x509 -days 7300 -key private/root-ca.key \
  -out certs/root-ca.crt -config openssl-root-ca.cnf

# Generate Intermediate CA key
cd ../intermediate-ca
openssl genpkey -algorithm RSA -pkcs8 -out private/intermediate-ca.key \
  -aes256 -pass pass:SECURE_PASSWORD

# Create Intermediate CA CSR
openssl req -new -key private/intermediate-ca.key \
  -out csr/intermediate-ca.csr -config openssl-intermediate-ca.cnf

# Sign Intermediate CA certificate with Root CA
cd ../root-ca
openssl ca -config openssl-root-ca.cnf -extensions v3_intermediate_ca \
  -days 3650 -notext -in ../intermediate-ca/csr/intermediate-ca.csr \
  -out ../intermediate-ca/certs/intermediate-ca.crt
```

#### OpenSSL Configuration for Root CA

```ini
# openssl-root-ca.cnf
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = $dir/private/root-ca.key
certificate       = $dir/certs/root-ca.crt

crlnumber         = $dir/crlnumber
crl               = $dir/crl/root-ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

### Issuing Certificates

```bash
# Generate server private key
openssl genpkey -algorithm RSA -out server.key -pkcs8

# Create Certificate Signing Request
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"

# Sign certificate with Intermediate CA
cd intermediate-ca
openssl ca -config openssl-intermediate-ca.cnf \
  -extensions server_cert -days 375 -notext \
  -in server.csr -out certs/server.crt

# Create certificate bundle (chain)
cat certs/server.crt ../intermediate-ca/certs/intermediate-ca.crt \
  ../root-ca/certs/root-ca.crt > server-chain.crt
```

### Certificate Revocation

```bash
# Revoke a certificate
openssl ca -config openssl-ca.cnf -revoke certs/compromised.crt

# Generate CRL
openssl ca -config openssl-ca.cnf -gencrl -out crl/ca.crl

# Verify CRL
openssl crl -in crl/ca.crl -noout -text

# Set up OCSP responder
openssl ocsp -port 8080 -text -sha256 \
  -index index.txt \
  -CA certs/ca-chain.crt \
  -rkey private/ocsp.key \
  -rsigner certs/ocsp.crt \
  -nrequest 1
```

## Certificate Lifecycle Management

### 1. Certificate Request

```bash
# Generate key and CSR
openssl req -new -newkey rsa:3072 -nodes \
  -keyout private.key -out request.csr \
  -subj "/CN=example.com/O=Organization/C=US" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

# Verify CSR
openssl req -text -noout -verify -in request.csr
```

### 2. Certificate Issuance

Validation levels:
- **DV (Domain Validation)**: Verify domain control only
- **OV (Organization Validation)**: Verify organization identity
- **EV (Extended Validation)**: Rigorous organization verification

### 3. Certificate Deployment

```bash
# Install certificate and key
sudo cp server.crt /etc/ssl/certs/
sudo cp server.key /etc/ssl/private/
sudo chmod 644 /etc/ssl/certs/server.crt
sudo chmod 600 /etc/ssl/private/server.key

# Configure Apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt
</VirtualHost>

# Configure Nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_trusted_certificate /etc/ssl/certs/intermediate.crt;
}
```

### 4. Certificate Renewal

```bash
# Check expiration
openssl x509 -enddate -noout -in server.crt

# Automated renewal with certbot (Let's Encrypt)
certbot renew --dry-run
certbot renew

# Manual renewal
openssl req -new -key server.key -out renewal.csr
# Submit to CA and replace certificate
```

### 5. Certificate Revocation

**Reasons for revocation:**
- Private key compromise
- CA compromise
- Change in affiliation
- Certificate superseded
- Cessation of operation

```bash
# Revoke via ACME (Let's Encrypt)
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

# Check revocation status via OCSP
openssl ocsp -issuer intermediate.crt -cert server.crt \
  -url http://ocsp.example.com -resp_text
```

## PKI Deployment Models

### 1. Single-Tier PKI

```
Root CA (Issues all certificates directly)
```

**Use Case**: Small organizations, testing
**Pros**: Simple, low overhead
**Cons**: Root key frequently used (security risk)

### 2. Two-Tier PKI

```
Root CA (Offline)
    └─ Issuing CA (Online)
```

**Use Case**: Medium organizations
**Pros**: Root key protected, reasonable security
**Cons**: Limited scalability

### 3. Three-Tier PKI

```
Root CA (Offline, highly protected)
    └─ Policy/Intermediate CA (Offline)
        └─ Issuing CA (Online, multiple)
```

**Use Case**: Large enterprises, high security requirements
**Pros**: Maximum security, scalability, flexibility
**Cons**: Complex management

### 4. Cloud-Based PKI

```
Cloud PKI Service (AWS ACM, Azure Key Vault, etc.)
```

**Advantages:**
- Managed service
- Automatic renewal
- Integration with cloud services
- Cost-effective for cloud-native applications

**Disadvantages:**
- Less control
- Vendor lock-in
- May not support all use cases

## Security Best Practices

### Root CA Protection

- **Offline Storage**: Keep Root CA completely offline
- **Physical Security**: Locked, monitored facility
- **Hardware Security Module (HSM)**: Store keys in FIPS 140-2 Level 3+ HSM
- **Ceremony Procedures**: Multi-person control for all Root CA operations
- **Backup**: Secure, geographically distributed backups

### Key Management

```bash
# Generate strong keys
openssl genpkey -algorithm RSA -pkcs8 -out key.pem \
  -aes256 -pass pass:STRONG_PASSWORD

# Set proper permissions
chmod 600 key.pem
chown root:root key.pem

# Use HSM for critical keys
pkcs11-tool --module /usr/lib/libCryptoki.so --login --keypairgen \
  --key-type RSA:3072 --label "CA-Key"
```

### Certificate Policy and Practice Statement

**Certificate Policy (CP)**: High-level requirements and rules

**Certificate Practice Statement (CPS)**: Detailed implementation procedures

**Key sections:**
1. Introduction and overview
2. Identification and authentication
3. Certificate lifecycle
4. Physical, procedural, and personnel security
5. Technical security controls
6. Audit and compliance

### Monitoring and Auditing

```bash
# Monitor certificate expiration
for cert in /etc/ssl/certs/*.crt; do
    echo "Certificate: $cert"
    openssl x509 -enddate -noout -in "$cert"
done

# Audit CA operations
grep "Certificate issued" /var/log/ca/audit.log

# Monitor OCSP responder
curl http://ocsp.example.com/status
```

### Certificate Transparency

```bash
# Submit certificate to CT log
ct-submit --cert server.crt --chain intermediate.crt

# Verify SCT (Signed Certificate Timestamp)
openssl x509 -ext SCT -in server.crt -noout -text

# Monitor CT logs
curl https://crt.sh/?q=example.com
```

## Troubleshooting Common Issues

### Certificate Chain Issues

```bash
# Problem: Incomplete certificate chain
# Solution: Verify and rebuild chain
openssl s_client -connect example.com:443 -showcerts

# Extract each certificate and build proper chain
cat server.crt intermediate.crt root.crt > complete-chain.crt
```

### Trust Store Issues

```bash
# Add custom CA to system trust store (Linux)
sudo cp root-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Add to Java trust store
keytool -import -trustcacerts -alias root-ca \
  -file root-ca.crt -keystore $JAVA_HOME/lib/security/cacerts

# Add to Firefox
# Preferences > Privacy & Security > Certificates > View Certificates > Import
```

### Certificate Mismatch

```bash
# Verify certificate matches private key
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# Hashes must match
```

### OCSP/CRL Issues

```bash
# Test OCSP responder
openssl ocsp -issuer intermediate.crt -cert server.crt \
  -url http://ocsp.example.com -resp_text -verify_other intermediate.crt

# Download and verify CRL
wget http://crl.example.com/crl.pem
openssl crl -inform PEM -in crl.pem -noout -text
```

## Additional Resources

- [RFC 5280 - Internet X.509 PKI Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - Online Certificate Status Protocol (OCSP)](https://tools.ietf.org/html/rfc6960)
- [NIST SP 800-57 - Key Management Recommendations](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/)
- [OpenSSL PKI Tutorial](https://pki-tutorial.readthedocs.io/)

