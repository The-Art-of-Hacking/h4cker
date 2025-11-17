# Lab 2: OpenSSL Certificate Operations

## Objectives
- Generate private keys
- Create Certificate Signing Requests (CSRs)
- Generate self-signed certificates
- Understand certificate structure
- Verify certificate chains

## Prerequisites
- OpenSSL installed
- Terminal/command line access
- Basic understanding of PKI concepts

## Estimated Time
45-60 minutes

## Lab Steps

### Step 1: Verify OpenSSL Installation

```bash
# Check OpenSSL version
openssl version

# Check available commands
openssl help
```

### Step 2: Generate Private Keys

#### RSA Key (Legacy)

```bash
# Create lab directory
mkdir ~/ssl-lab
cd ~/ssl-lab

# Generate 3072-bit RSA private key
openssl genpkey -algorithm RSA -pkcs8 -out server.key

# View key details
openssl pkey -in server.key -text -noout

# Generate encrypted private key
openssl genpkey -algorithm RSA -pkcs8 -out server-encrypted.key \
  -aes256 -pass pass:lab_password

# Try to view encrypted key
cat server-encrypted.key
```

**Questions:**
1. What is the key size?
2. What is the public exponent value?
3. Why should private keys be encrypted?

#### EC Key (Modern)

```bash
# List available curves
openssl ecparam -list_curves

# Generate EC private key (P-256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out ec_server.key

# View EC key details
openssl pkey -in ec_server.key -text -noout
```

### Step 3: Extract Public Key

```bash
# Extract public key from RSA private key
openssl pkey -in server.key -pubout -out server_public.key

# View public key
cat server_public.key

# Extract public key from EC private key
openssl pkey -in ec_server.key -pubout -out ec_server_public.key
```

### Step 4: Create Certificate Signing Request (CSR)

```bash
# Interactive CSR creation
openssl req -new -key server.key -out server.csr

# Non-interactive CSR with subject
openssl req -new -key server.key -out server2.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Lab Organization/OU=IT Department/CN=lab.example.com"

# View CSR details
openssl req -text -noout -in server.csr

# Verify CSR
openssl req -verify -in server.csr -text -noout
```

**Questions:**
1. What information is included in the CSR?
2. What is the Common Name (CN) field used for?
3. Does the CSR contain the private key?

### Step 5: Generate Self-Signed Certificate

```bash
# Create self-signed certificate (1 year validity)
openssl req -new -x509 -days 365 -key server.key \
  -out server.crt \
  -subj "/C=US/ST=California/L=San Francisco/O=Lab Organization/CN=lab.example.com"

# View certificate details
openssl x509 -text -noout -in server.crt

# View specific certificate fields
echo "Subject:"
openssl x509 -subject -noout -in server.crt
echo "Issuer:"
openssl x509 -issuer -noout -in server.crt
echo "Validity:"
openssl x509 -dates -noout -in server.crt
echo "Serial Number:"
openssl x509 -serial -noout -in server.crt
```

### Step 6: Certificate with Subject Alternative Names (SANs)

```bash
# Create OpenSSL config file
cat > san.cnf << EOF
[req]
default_bits = 3072
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=California
L=San Francisco
O=Lab Organization
CN=lab.example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = lab.example.com
DNS.2 = www.lab.example.com
DNS.3 = api.lab.example.com
IP.1 = 192.168.1.100
EOF

# Generate CSR with SANs
openssl req -new -key server.key -out server_san.csr -config san.cnf

# Generate self-signed certificate with SANs
openssl req -new -x509 -days 365 -key server.key \
  -out server_san.crt -config san.cnf -extensions v3_req

# View SANs
openssl x509 -text -noout -in server_san.crt | grep -A 4 "Subject Alternative Name"
```

**Questions:**
1. Why are SANs important?
2. Can you include IP addresses in SANs?

### Step 7: Create a Simple CA

```bash
# Create CA directory structure
mkdir -p myca/{certs,crl,newcerts,private}
cd myca
touch index.txt
echo 1000 > serial

# Generate CA private key
openssl genpkey -algorithm RSA -pkcs8 -out private/ca.key -aes256

# Create CA certificate
openssl req -new -x509 -days 3650 -key private/ca.key \
  -out certs/ca.crt \
  -subj "/C=US/ST=California/O=Lab CA/CN=Lab Root CA"
```

### Step 8: Sign Certificate with Your CA

```bash
# Create OpenSSL CA config
cat > openssl-ca.cnf << 'EOF'
[ca]
default_ca = CA_default

[CA_default]
dir              = .
certs            = $dir/certs
crl_dir          = $dir/crl
new_certs_dir    = $dir/newcerts
database         = $dir/index.txt
serial           = $dir/serial
private_key      = $dir/private/ca.key
certificate      = $dir/certs/ca.crt
default_md       = sha256
default_days     = 365
policy           = policy_loose

[policy_loose]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# Copy the CSR from previous steps
cp ../server.csr .

# Sign the certificate
openssl ca -config openssl-ca.cnf -extensions server_cert \
  -days 365 -notext -in server.csr -out certs/server_signed.crt

# View signed certificate
openssl x509 -text -noout -in certs/server_signed.crt
```

### Step 9: Certificate Verification

```bash
# Verify certificate against CA
openssl verify -CAfile certs/ca.crt certs/server_signed.crt

# Check if certificate and key match
openssl x509 -noout -modulus -in certs/server_signed.crt | openssl md5
openssl rsa -noout -modulus -in ../server.key | openssl md5
# MD5 hashes should match

# Create certificate chain
cat certs/server_signed.crt certs/ca.crt > certs/server_chain.crt

# Verify chain
openssl verify -CAfile certs/ca.crt certs/server_chain.crt
```

### Step 10: Certificate Format Conversion

```bash
cd ~/ssl-lab

# PEM to DER
openssl x509 -outform der -in myca/certs/server_signed.crt \
  -out server.der

# DER to PEM
openssl x509 -inform der -in server.der -out server_from_der.pem

# Create PKCS#12 bundle (contains certificate + private key)
openssl pkcs12 -export -out server.p12 \
  -inkey server.key \
  -in myca/certs/server_signed.crt \
  -certfile myca/certs/ca.crt \
  -name "Lab Server Certificate"

# View PKCS#12 contents
openssl pkcs12 -info -in server.p12

# Extract certificate from PKCS#12
openssl pkcs12 -in server.p12 -clcerts -nokeys -out extracted_cert.pem

# Extract private key from PKCS#12
openssl pkcs12 -in server.p12 -nocerts -nodes -out extracted_key.pem
```

## Challenges

### Challenge 1: Create an Intermediate CA

```bash
# 1. Generate intermediate CA key
# 2. Create intermediate CA CSR
# 3. Sign intermediate CA certificate with root CA
# 4. Issue end-entity certificate from intermediate CA
# 5. Verify full chain: end-entity → intermediate → root

# Hints:
# - Use -extensions v3_intermediate_ca
# - Set pathlen:0 in basicConstraints
# - Create 3-level chain
```

### Challenge 2: Certificate Expiration Analysis

```bash
# Create certificates with different validity periods
# Check which certificates are expiring soon
# Write a script to monitor certificate expiration

find ~/ssl-lab -name "*.crt" -o -name "*.pem" | while read cert; do
    echo "Certificate: $cert"
    openssl x509 -enddate -noout -in "$cert" 2>/dev/null
    echo ""
done
```

### Challenge 3: Multi-Domain Certificate

```bash
# Create a single certificate valid for:
# - example.com
# - www.example.com
# - mail.example.com
# - *.internal.example.com (wildcard)
# - 10.0.0.1 (IP address)

# Verify all SANs are present
```

## Verification Checklist

- [ ] Generated RSA and EC private keys
- [ ] Created CSRs
- [ ] Generated self-signed certificates
- [ ] Created certificates with SANs
- [ ] Set up a simple CA
- [ ] Signed certificates with your CA
- [ ] Verified certificate chains
- [ ] Converted certificate formats
- [ ] Completed at least one challenge

## Key Takeaways

1. **Private keys must be protected** - Never share or expose them
2. **CSRs contain public key and identity information** - Not the private key
3. **Self-signed certificates** - Useful for testing, not for production
4. **SANs are essential** - Modern browsers require them
5. **Certificate chains** - Trust flows from root to end-entity
6. **Format conversions** - PEM, DER, PKCS#12 serve different purposes

## Common Issues and Solutions

### Issue: "unable to write 'random state'"
**Solution:** Insufficient permissions or disk space. Check directory permissions.

### Issue: "error:0906D06C:PEM routines:PEM_read_bio:no start line"
**Solution:** Wrong file format or corrupted file. Verify file content.

### Issue: Certificate verification failed
**Solution:** Check certificate chain order, ensure CA certificate is trusted.

## Next Steps

Proceed to:
- Lab 3: TLS/SSL Server Configuration
- Lab 4: Certificate Revocation (CRL and OCSP)
- Lab 5: Post-Quantum Cryptography Basics

## Additional Resources

- [OpenSSL Cookbook](https://www.feistyduck.com/books/openssl-cookbook/)
- [OpenSSL Command Reference](https://www.openssl.org/docs/manmaster/man1/)
- [PKI Tutorial](https://pki-tutorial.readthedocs.io/)

