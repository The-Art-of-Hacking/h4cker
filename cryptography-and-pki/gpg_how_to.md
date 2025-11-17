# Complete GPG Guide: Keys, Encryption, and Trust Management

This comprehensive guide covers GPG (GNU Privacy Guard) operations from basic key generation to advanced trust management, key server interactions, and secure backup procedures. GPG provides robust encryption, digital signatures, and key management capabilities essential for secure communications.

## Table of Contents
- [Key Generation](#generating-gpg-keys)
- [File Encryption/Decryption](#encrypting-and-decrypting-files)
- [Key Server Operations](#key-server-interaction)
- [Web of Trust](#digital-signatures-and-web-of-trust)
- [Backup and Recovery](#backup-and-recovery-procedures)
- [Advanced Operations](#advanced-operations)
- [Security Best Practices](#security-best-practices)

## Generating GPG Keys

### Installation

**Linux (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt install gnupg
```

**macOS:**
```bash
brew install gnupg
```

**Windows:**
Download from [GnuPG.org](https://gnupg.org/download/) or use Chocolatey:
```powershell
choco install gnupg
```

### Basic Key Generation

⚠️ **Security Notice**: RSA is quantum-vulnerable. Consider ECC for better security, but plan for post-quantum migration.

```bash
# Interactive key generation
gpg --full-generate-key

# Quick key generation with defaults
gpg --quick-generate-key "Your Name <email@example.com>" rsa4096 encrypt,sign 2y
```

### Advanced Key Generation

```bash
# Generate ECC key (better security, smaller size)
gpg --full-generate-key
# Select: (9) ECC (sign and encrypt)
# Choose: (1) Curve 25519

# Generate key with specific parameters
gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Your Full Name
Name-Email: your.email@example.com
Expire-Date: 2y
Passphrase: PASSPHRASE_FROM_SECURE_SOURCE
%commit
EOF
```

### Key Generation Best Practices

- **Key Size**: Minimum 3072 bits for RSA, prefer 4096 bits
- **Expiration**: Set 1-2 year expiration for regular renewal
- **Passphrase**: Use strong, unique passphrase (consider using a password manager)
- **Backup**: Immediately backup your keys after generation

### Viewing Your Keys

```bash
# List public keys
gpg --list-keys

# List private keys
gpg --list-secret-keys

# Show key details with fingerprints
gpg --list-keys --fingerprint

# Show key with signatures
gpg --list-sigs your.email@example.com
```

## Encrypting and Decrypting Files

### Basic File Encryption

```bash
# Encrypt for specific recipient
gpg --encrypt --recipient recipient@example.com file.txt

# Encrypt for multiple recipients
gpg --encrypt --recipient alice@example.com --recipient bob@example.com file.txt

# Encrypt and armor (ASCII output)
gpg --encrypt --armor --recipient recipient@example.com file.txt

# Encrypt for yourself (useful for secure storage)
gpg --encrypt --recipient your.email@example.com file.txt
```

### Symmetric Encryption

```bash
# Encrypt with passphrase only (no public key needed)
gpg --symmetric file.txt

# Specify cipher algorithm
gpg --symmetric --cipher-algo AES256 file.txt
```

### File Decryption

```bash
# Decrypt file
gpg --decrypt file.txt.gpg > decrypted_file.txt

# Decrypt and verify signature
gpg --decrypt file.txt.gpg

# Decrypt to specific output file
gpg --output decrypted_file.txt --decrypt file.txt.gpg
```

### Advanced Encryption Options

```bash
# Encrypt and sign in one operation
gpg --encrypt --sign --recipient recipient@example.com file.txt

# Encrypt with compression
gpg --encrypt --compress-algo 2 --recipient recipient@example.com file.txt

# Encrypt directory (tar + gpg)
tar czf - directory/ | gpg --encrypt --recipient recipient@example.com > directory.tar.gz.gpg
```

## Key Server Interaction

### Popular Key Servers

- **keys.openpgp.org** (recommended, privacy-focused)
- **keyserver.ubuntu.com**
- **pgp.mit.edu**
- **keys.gnupg.net**

### Uploading Keys

```bash
# Upload your public key to default keyserver
gpg --send-keys YOUR_KEY_ID

# Upload to specific keyserver
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID

# Upload all public keys
gpg --send-keys
```

### Searching and Downloading Keys

```bash
# Search for keys by email
gpg --search-keys user@example.com

# Search on specific keyserver
gpg --keyserver keys.openpgp.org --search-keys user@example.com

# Download key by ID
gpg --recv-keys KEY_ID

# Download from specific keyserver
gpg --keyserver keys.openpgp.org --recv-keys KEY_ID
```

### Key Verification

```bash
# Always verify fingerprint after downloading
gpg --fingerprint user@example.com

# Check key signatures
gpg --check-sigs user@example.com

# Verify key through multiple sources
gpg --keyserver keys.openpgp.org --recv-keys KEY_ID
gpg --keyserver keyserver.ubuntu.com --recv-keys KEY_ID
```

### Key Server Configuration

```bash
# Set default keyserver in ~/.gnupg/gpg.conf
echo "keyserver hkps://keys.openpgp.org" >> ~/.gnupg/gpg.conf

# Configure keyserver options
echo "keyserver-options auto-key-retrieve" >> ~/.gnupg/gpg.conf
echo "keyserver-options honor-keyserver-url" >> ~/.gnupg/gpg.conf
```

## Digital Signatures and Web of Trust

### Creating Digital Signatures

```bash
# Sign a file (creates .sig file)
gpg --sign file.txt

# Create detached signature
gpg --detach-sign file.txt

# Create ASCII-armored detached signature
gpg --armor --detach-sign file.txt

# Clear-sign text file (signature embedded)
gpg --clearsign message.txt
```

### Verifying Signatures

```bash
# Verify signature and extract original file
gpg --verify file.txt.sig

# Verify detached signature
gpg --verify file.txt.sig file.txt

# Verify and show signature details
gpg --status-fd 1 --verify file.txt.sig file.txt
```

### Key Signing and Web of Trust

#### Signing Others' Keys

```bash
# Sign someone's key (after verification)
gpg --sign-key user@example.com

# Sign with specific certification level
gpg --ask-cert-level --sign-key user@example.com

# Create exportable signature
gpg --sign-key --ask-cert-level user@example.com
```

#### Trust Levels

```bash
# Set trust level for a key
gpg --edit-key user@example.com
# In GPG prompt: trust
# Select trust level (1-5):
# 1 = I don't know or won't say
# 2 = I do NOT trust
# 3 = I trust marginally
# 4 = I trust fully
# 5 = I trust ultimately
```

#### Key Signing Best Practices

1. **Verify Identity**: Always verify the person's identity through multiple channels
2. **Check Fingerprint**: Compare fingerprints in person or through secure channels
3. **Understand Implications**: Your signature vouches for the key's authenticity
4. **Use Appropriate Trust Level**: Be conservative with trust assignments

### Web of Trust Management

```bash
# Show trust database
gpg --export-ownertrust

# Import trust database
gpg --import-ownertrust trust.txt

# Update trust database
gpg --update-trustdb

# Check key validity
gpg --check-trustdb
```

## Backup and Recovery Procedures

⚠️ **CRITICAL SECURITY NOTICE**: Private key backups are extremely sensitive. Any compromise of a backup exposes your entire cryptographic identity. Always follow these principles:

- **Never digitally photograph or scan private keys**
- **Avoid QR codes for private key storage** (easily captured by cameras)
- **Use secure, offline storage methods only**
- **Test recovery procedures regularly**
- **Consider the physical security of backup locations**

### Backing Up Keys

```bash
# Export public key
gpg --export --armor your.email@example.com > public_key.asc

# Export private key (KEEP SECURE!)
gpg --export-secret-keys --armor your.email@example.com > private_key.asc

# Export all keys
gpg --export-secret-keys --armor > all_private_keys.asc
gpg --export --armor > all_public_keys.asc

# Export specific subkeys
gpg --export-secret-subkeys --armor KEY_ID > subkeys.asc
```

### Secure Backup Strategies

#### Method 1: Encrypted Backup

```bash
# Create encrypted backup of keyring
tar czf - ~/.gnupg | gpg --symmetric --cipher-algo AES256 > gnupg_backup.tar.gz.gpg

# Restore from encrypted backup
gpg --decrypt gnupg_backup.tar.gz.gpg | tar xzf - -C ~/
```

#### Method 2: Paper Backup (Recommended for Offline Storage)

⚠️ **SECURITY WARNING**: Never create QR codes of private keys! QR codes can be easily photographed or scanned by unauthorized parties, potentially exposing your private key.

```bash
# RECOMMENDED: Use paperkey for secure, human-readable paper backup
gpg --export-secret-keys KEY_ID | paperkey --output-type raw > key_backup.txt

# Alternative: Export in ASCII armor format for manual transcription
gpg --export-secret-keys --armor KEY_ID > key_backup.asc

# Print the text file and store in a secure, offline location
# Consider splitting the backup across multiple secure locations
```

**Paper Backup Best Practices:**
- Use paperkey for compact, human-readable format
- Print on acid-free paper for longevity
- Store in multiple secure, geographically distributed locations
- Consider lamination or other physical protection
- Never photograph or scan the backup
- Test recovery process periodically

#### Method 3: Hardware Security Module (HSM)

```bash
# Move keys to smart card/hardware token
gpg --card-edit
# Use 'admin' and 'generate' commands
```

### Recovery Procedures

```bash
# Import backed up keys
gpg --import public_key.asc
gpg --import private_key.asc

# Restore from paper backup (using paperkey)
paperkey --pubring public_key.asc --secrets key_backup.txt | gpg --import

# Verify restored keys
gpg --list-secret-keys
gpg --list-keys
```

### Key Revocation

```bash
# Generate revocation certificate (do this immediately after key creation)
gpg --gen-revoke your.email@example.com > revocation_cert.asc

# Revoke compromised key
gpg --import revocation_cert.asc
gpg --send-keys KEY_ID  # Upload revocation to keyservers
```

## Advanced Operations

### Subkey Management

```bash
# Add encryption subkey
gpg --edit-key your.email@example.com
# In GPG prompt: addkey

# Add signing subkey
gpg --edit-key your.email@example.com
# In GPG prompt: addkey

# Delete subkey
gpg --edit-key your.email@example.com
# In GPG prompt: key N (select subkey), delkey
```

### Key Editing

```bash
# Edit key (add UID, change expiration, etc.)
gpg --edit-key your.email@example.com

# Common edit commands:
# adduid     - Add user ID
# deluid     - Delete user ID
# primary    - Set primary user ID
# expire     - Change expiration date
# passwd     - Change passphrase
# save       - Save changes
```

### Batch Operations

```bash
# Batch encrypt multiple files
for file in *.txt; do
    gpg --encrypt --recipient user@example.com "$file"
done

# Batch decrypt multiple files
for file in *.gpg; do
    gpg --decrypt "$file" > "${file%.gpg}"
done
```

## Security Best Practices

### Key Management

- **Use Strong Passphrases**: Minimum 12 characters, use password manager
- **Set Expiration Dates**: 1-2 years maximum, renew regularly
- **Create Revocation Certificates**: Generate immediately after key creation
- **Backup Securely**: Multiple secure locations, test recovery procedures

### Operational Security

- **Verify Fingerprints**: Always verify through multiple channels
- **Use Trusted Systems**: Generate keys on secure, offline systems when possible
- **Regular Updates**: Keep GPG software updated
- **Monitor Key Usage**: Regularly check for unauthorized signatures

### Communication Security

- **Encrypt Sensitive Data**: Always encrypt confidential information
- **Sign Important Messages**: Use signatures for authenticity
- **Verify Signatures**: Always verify signatures on received messages
- **Use Secure Channels**: Verify fingerprints through secure, out-of-band channels

### Privacy Considerations

- **Metadata Protection**: Be aware that encryption reveals communication patterns
- **Key Server Privacy**: Consider privacy implications of uploading to key servers
- **Forward Secrecy**: Consider using protocols with forward secrecy for real-time communication

## Troubleshooting Common Issues

### Key Import/Export Issues

```bash
# Fix permission issues
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*

# Refresh expired keys
gpg --refresh-keys

# Clean up keyring
gpg --delete-keys KEY_ID
```

### Encryption/Decryption Problems

```bash
# Check available keys
gpg --list-keys recipient@example.com

# Verify key trust
gpg --edit-key recipient@example.com
# In GPG prompt: trust

# Debug encryption issues
gpg --verbose --encrypt --recipient recipient@example.com file.txt
```

## Additional Resources

- [GPG Documentation](https://gnupg.org/documentation/)
- [OpenPGP Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)
- [GPG/PGP Basics](https://www.gnupg.org/gph/en/manual.html)
- [Key Signing Party HOWTO](https://www.cryptnet.net/fdp/crypto/keysigning_party/en/keysigning_party.html)
