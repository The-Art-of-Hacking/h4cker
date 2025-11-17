# Comprehensive Disk and Data Encryption Guide

This guide covers modern disk encryption solutions, from full-disk encryption to file-level protection, including post-quantum considerations, mobile device security, and enterprise key management strategies.

## Table of Contents
- [Full Disk Encryption](#full-disk-encryption)
- [File-Level Encryption](#file-level-encryption)
- [Mobile Device Encryption](#mobile-device-encryption)
- [Post-Quantum Encryption](#post-quantum-encryption-options)
- [Enterprise Key Management](#enterprise-key-management)
- [Cloud Storage Encryption](#cloud-storage-encryption)
- [Implementation Guides](#implementation-guides)
- [Security Best Practices](#security-best-practices)

## Full Disk Encryption

### VeraCrypt (Recommended)
**Cross-platform, quantum-resistant ready**

```bash
# Linux installation
sudo apt install veracrypt

# Create encrypted volume
veracrypt --create /path/to/encrypted.volume --size 1G --encryption AES --hash SHA-512

# Mount encrypted volume
veracrypt /path/to/encrypted.volume /mnt/encrypted

# Dismount
veracrypt --dismount /mnt/encrypted
```

**Features:**
- AES-256, Serpent, Twofish encryption
- Hidden volumes for plausible deniability
- System encryption (full disk)
- Cross-platform compatibility

### LUKS (Linux Unified Key Setup)
**Linux native, high performance**

```bash
# Create LUKS encrypted partition
sudo cryptsetup luksFormat /dev/sdX1

# Open encrypted partition
sudo cryptsetup luksOpen /dev/sdX1 encrypted_drive

# Mount filesystem
sudo mount /dev/mapper/encrypted_drive /mnt/encrypted

# Close encrypted partition
sudo cryptsetup luksClose encrypted_drive
```

**Advanced LUKS Operations:**
```bash
# Add additional key slot
sudo cryptsetup luksAddKey /dev/sdX1

# Remove key slot
sudo cryptsetup luksRemoveKey /dev/sdX1

# Backup LUKS header
sudo cryptsetup luksHeaderBackup /dev/sdX1 --header-backup-file luks_header.backup

# Restore LUKS header
sudo cryptsetup luksHeaderRestore /dev/sdX1 --header-backup-file luks_header.backup
```

### BitLocker Alternatives
**For Windows environments**

- **VeraCrypt**: Cross-platform alternative
- **DiskCryptor**: Open-source Windows disk encryption
- **AxCrypt**: File-level encryption for Windows

## File-Level Encryption

### Cryptomator
**Cloud storage encryption**

```bash
# Install Cryptomator
# Download from https://cryptomator.org/

# Create vault
cryptomator-cli --vault /path/to/vault --password your_password unlock

# Access encrypted files through mounted directory
ls /path/to/mounted/vault
```

**Features:**
- Transparent cloud storage encryption
- Cross-platform compatibility
- AES-256 encryption
- Filename encryption

### EncFS
**FUSE-based encrypted filesystem**

```bash
# Install EncFS
sudo apt install encfs

# Create encrypted directory
encfs ~/.encrypted ~/decrypted

# Mount existing encrypted directory
encfs ~/.encrypted ~/decrypted

# Unmount
fusermount -u ~/decrypted
```

### Git-Crypt
**Git repository encryption**

```bash
# Initialize git-crypt in repository
git-crypt init

# Add files to encrypt (in .gitattributes)
echo "secrets/* filter=git-crypt diff=git-crypt" >> .gitattributes

# Add GPG user
git-crypt add-gpg-user your.email@example.com

# Lock repository
git-crypt lock

# Unlock repository
git-crypt unlock
```

### SOPS (Secrets OPerationS)
**Structured data encryption**

```bash
# Install SOPS
# Download from https://github.com/mozilla/sops/releases

# Encrypt YAML file with GPG
sops --encrypt --pgp your_key_id secrets.yaml > secrets.enc.yaml

# Encrypt with AWS KMS
sops --encrypt --kms arn:aws:kms:region:account:key/key-id secrets.yaml > secrets.enc.yaml

# Decrypt file
sops --decrypt secrets.enc.yaml

# Edit encrypted file
sops secrets.enc.yaml
```

## Mobile Device Encryption

### iOS Encryption
**Built-in encryption management**

**Security Features:**
- Hardware-based encryption (A7+ chips)
- Secure Enclave for key management
- Data Protection API
- FileVault equivalent protection

### Android Encryption
**Device and file-level encryption**

```bash
# Check encryption status
adb shell getprop ro.crypto.state

# Enable file-based encryption (Android 7+)
# Automatically enabled on modern devices
```

**Encryption Types:**
- **Full Disk Encryption (FDE)**: Legacy, encrypts entire userdata partition
- **File-Based Encryption (FBE)**: Modern, per-file encryption
- **Hardware-backed Keystore**: TEE/SE integration

### Mobile Device Management (MDM)
**Enterprise mobile encryption**

- **Microsoft Intune**: BitLocker management, iOS/Android encryption policies
- **VMware Workspace ONE**: Container-based encryption, app-level data protection
- **Google Workspace**: Android device encryption management

## Post-Quantum Encryption Options

### Quantum-Resistant Algorithms
**Future-proofing encryption**

⚠️ **Migration Timeline**: Begin planning post-quantum migration by 2025-2027.

```bash
# OpenSSL with OQS provider (experimental)
# Install Open Quantum Safe provider
git clone https://github.com/open-quantum-safe/oqs-provider.git

# Generate post-quantum keys
openssl genpkey -algorithm kyber512 -out pq_key.pem

# Hybrid encryption (classical + post-quantum)
# Combine AES-256 with Kyber for key encapsulation
```

### Post-Quantum Tools
**Emerging solutions**

- **liboqs**: Open Quantum Safe library
- **PQClean**: Clean implementations of post-quantum crypto
- **NIST PQC Reference Implementations**: Official algorithm implementations
- **Hybrid TLS**: TLS with post-quantum key exchange

## Enterprise Key Management

### Hardware Security Modules (HSMs)
**Enterprise-grade key protection**

```bash
# AWS CloudHSM
aws cloudhsm create-cluster --hsm-type hsm1.medium

# Azure Dedicated HSM
az keyvault create --name MyKeyVault --resource-group MyResourceGroup

# On-premises HSM (SafeNet, Thales)
# Integration through PKCS#11 interface
```

**HSM Benefits:**
- FIPS 140-2 Level 3/4 compliance
- Hardware-based key generation
- Tamper-resistant/evident hardware
- High-performance cryptographic operations

### Key Management Systems (KMS)
**Centralized key lifecycle management**

#### AWS KMS
```bash
# Create customer managed key
aws kms create-key --description "Disk encryption key"

# Encrypt data
aws kms encrypt --key-id alias/my-key --plaintext "sensitive data"

# Decrypt data
aws kms decrypt --ciphertext-blob encrypted_data
```

#### HashiCorp Vault
```bash
# Enable transit secrets engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/my-key

# Encrypt data
vault write transit/encrypt/my-key plaintext=$(base64 <<< "sensitive data")

# Decrypt data
vault write transit/decrypt/my-key ciphertext="vault:v1:encrypted_data"
```

#### Azure Key Vault
```bash
# Create key vault
az keyvault create --name MyKeyVault --resource-group MyResourceGroup

# Create key
az keyvault key create --vault-name MyKeyVault --name MyKey --protection software

# Encrypt with key
az keyvault key encrypt --vault-name MyKeyVault --name MyKey --algorithm RSA-OAEP --value "sensitive data"
```

## Cloud Storage Encryption

### Client-Side Encryption Tools

#### Rclone with Crypt
```bash
# Install rclone
curl https://rclone.org/install.sh | sudo bash

# Configure encrypted remote
rclone config
# Choose crypt backend
# Configure underlying remote (Google Drive, S3, etc.)
# Set encryption parameters

# Sync with encryption
rclone sync /local/path encrypted-remote:
```

#### Duplicati
```bash
# Install Duplicati
# Download from https://www.duplicati.com/

# Backup with encryption
duplicati-cli backup s3://bucket/path /source/path \
  --encryption-module=aes \
  --passphrase=your_passphrase \
  --compression-module=zip
```

### Zero-Knowledge Cloud Storage
**Privacy-focused solutions**

- **SpiderOak**: Zero-knowledge backup and sync
- **Tresorit**: End-to-end encrypted cloud storage
- **pCloud Crypto**: Client-side encryption add-on
- **Sync.com**: Built-in zero-knowledge encryption

## Implementation Guides

### Setting Up Full Disk Encryption

#### Linux (LUKS) Setup
```bash
#!/bin/bash
# Full disk encryption setup script

# Partition disk
sudo fdisk /dev/sdX
# Create boot partition (500MB) and root partition

# Format boot partition
sudo mkfs.ext4 /dev/sdX1

# Setup LUKS on root partition
sudo cryptsetup luksFormat /dev/sdX2
sudo cryptsetup luksOpen /dev/sdX2 root

# Create filesystem
sudo mkfs.ext4 /dev/mapper/root

# Mount for installation
sudo mount /dev/mapper/root /mnt
sudo mkdir /mnt/boot
sudo mount /dev/sdX1 /mnt/boot

# Install system (distribution-specific)
# Configure bootloader for LUKS
```

#### EncFS Container
```bash
#!/bin/bash
# Create portable encrypted container

# Create directories
mkdir -p ~/encrypted_container/encrypted
mkdir -p ~/encrypted_container/decrypted

# Initialize EncFS
encfs ~/encrypted_container/encrypted ~/encrypted_container/decrypted

# Create mount script
cat > ~/encrypted_container/mount.sh << 'EOF'
#!/bin/bash
encfs ~/encrypted_container/encrypted ~/encrypted_container/decrypted
EOF

# Create unmount script
cat > ~/encrypted_container/unmount.sh << 'EOF'
#!/bin/bash
fusermount -u ~/encrypted_container/decrypted
EOF

chmod +x ~/encrypted_container/*.sh
```

## Security Best Practices

### Key Management
- **Strong Passphrases**: Minimum 12 characters, use password managers
- **Key Rotation**: Regular rotation schedule (annually for disk encryption)
- **Backup Keys**: Secure offline backup of recovery keys
- **Multi-Factor Authentication**: Additional authentication layers

### Encryption Standards
- **Algorithm Selection**: AES-256 minimum, prepare for post-quantum
- **Key Derivation**: PBKDF2, scrypt, or Argon2 for password-based keys
- **Random Number Generation**: Hardware-based RNG when available
- **Forward Secrecy**: Consider protocols with forward secrecy

### Operational Security
- **Secure Boot**: Enable secure boot to prevent bootloader attacks
- **TPM Integration**: Use TPM for key storage when available
- **Regular Updates**: Keep encryption software updated
- **Monitoring**: Monitor for unauthorized access attempts

### Compliance Considerations
- **FIPS 140-2**: Use FIPS-validated encryption modules for government/regulated industries
- **Common Criteria**: Consider CC-evaluated products for high-security environments
- **GDPR/CCPA**: Implement encryption for personal data protection
- **Industry Standards**: Follow sector-specific encryption requirements

## Troubleshooting Common Issues

### LUKS Recovery
```bash
# Recover from corrupted LUKS header
sudo cryptsetup luksHeaderRestore /dev/sdX1 --header-backup-file luks_header.backup

# Add emergency key slot
sudo cryptsetup luksAddKey /dev/sdX1

# Check LUKS header
sudo cryptsetup luksDump /dev/sdX1
```

### VeraCrypt Issues
```bash
# Mount with specific filesystem
veracrypt --filesystem=ntfs /path/to/volume /mnt/point

# Force dismount
veracrypt --force --dismount /mnt/point

# Repair filesystem
fsck /dev/mapper/veracrypt1
```

### Performance Optimization
```bash
# Enable AES-NI hardware acceleration
grep -m1 -o aes /proc/cpuinfo

# Optimize LUKS cipher
sudo cryptsetup benchmark

# Use faster hash algorithms
sudo cryptsetup luksFormat --hash sha256 /dev/sdX1
```

## Additional Resources

- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [VeraCrypt Documentation](https://www.veracrypt.fr/en/Documentation.html)
- [LUKS/dm-crypt Documentation](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/home)
- [Post-Quantum Cryptography Migration](https://csrc.nist.gov/Projects/post-quantum-cryptography)
