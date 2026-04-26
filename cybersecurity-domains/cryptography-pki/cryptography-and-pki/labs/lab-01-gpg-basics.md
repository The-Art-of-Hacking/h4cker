# Lab 1: GPG Basics - Key Generation and File Encryption

## Objectives
- Generate a GPG key pair
- Encrypt and decrypt files
- Export and import keys
- Understand key management

## Prerequisites
- Linux, macOS, or Windows with GPG installed
- Terminal/command line access
- Basic understanding of public key cryptography

## Estimated Time
30-45 minutes

## Lab Steps

### Step 1: Install GPG (if not already installed)

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install gnupg
```

**macOS:**
```bash
brew install gnupg
```

**Windows:**
Download from https://gnupg.org/download/ or use Chocolatey:
```powershell
choco install gnupg
```

**Verify Installation:**
```bash
gpg --version
```

### Step 2: Generate Your First Key Pair

```bash
# Start interactive key generation
gpg --full-generate-key

# Follow the prompts:
# 1. Select key type: (1) RSA and RSA (default)
# 2. Key size: 3072 or 4096 bits
# 3. Key expiration: 2y (2 years)
# 4. Real name: Your Name
# 5. Email: your.email@example.com
# 6. Comment: Lab Exercise Key
# 7. Passphrase: Create a strong passphrase
```

**Expected Output:**
```
gpg: key 1234ABCD5678EFGH marked as ultimately trusted
gpg: directory '/home/user/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/1234ABCD5678EFGH.rev'
public and secret key created and signed.
```

### Step 3: List Your Keys

```bash
# List public keys
gpg --list-keys

# List secret keys
gpg --list-secret-keys

# Show key details with fingerprints
gpg --list-keys --fingerprint
```

**Questions:**
1. What is your key ID?
2. What is your key fingerprint?
3. When does your key expire?

### Step 4: Create Test Files

```bash
# Create a directory for lab files
mkdir ~/gpg-lab
cd ~/gpg-lab

# Create a test file
echo "This is a secret message for GPG Lab 1" > secret.txt
cat secret.txt
```

### Step 5: Encrypt a File

```bash
# Encrypt for yourself
gpg --encrypt --recipient your.email@example.com secret.txt

# Verify encrypted file was created
ls -la secret.txt.gpg

# Try to view encrypted file (won't be readable)
cat secret.txt.gpg
hexdump -C secret.txt.gpg | head
```

**Questions:**
1. What is the file extension of the encrypted file?
2. Can you read the encrypted file with `cat`?

### Step 6: Decrypt the File

```bash
# Decrypt the file
gpg --decrypt secret.txt.gpg > decrypted.txt

# You will be prompted for your passphrase
# Compare original and decrypted files
diff secret.txt decrypted.txt

# Alternative: decrypt to stdout
gpg --decrypt secret.txt.gpg
```

**Expected Result:** The decrypted content should match the original file exactly.

### Step 7: ASCII Armor Encryption

```bash
# Encrypt with ASCII armor (text format)
gpg --encrypt --armor --recipient your.email@example.com secret.txt

# This creates secret.txt.asc instead of .gpg
cat secret.txt.asc
```

**Questions:**
1. What is the difference between `.gpg` and `.asc` files?
2. When would you use ASCII armor format?

### Step 8: Export Your Public Key

```bash
# Export public key in ASCII format
gpg --export --armor your.email@example.com > public_key.asc

# View the exported key
cat public_key.asc

# Export public key in binary format
gpg --export your.email@example.com > public_key.gpg
```

### Step 9: Symmetric Encryption (Bonus)

```bash
# Create a new test file
echo "Symmetric encryption test" > symmetric_test.txt

# Encrypt with passphrase only (no public key)
gpg --symmetric symmetric_test.txt

# Decrypt
gpg --decrypt symmetric_test.txt.gpg
```

**Question:** When would you use symmetric encryption instead of public key encryption?

### Step 10: Clean Up and Generate Revocation Certificate

```bash
# Generate revocation certificate (IMPORTANT!)
gpg --gen-revoke your.email@example.com > revocation_cert.asc

# Save this file in a secure location!
```

## Challenges

### Challenge 1: Multiple Recipients

```bash
# Generate a second key pair for testing
gpg --quick-generate-key "Test User <test@example.com>" rsa3072 encrypt,sign 1y

# Create a file and encrypt for multiple recipients
echo "Multi-recipient test" > multi.txt
gpg --encrypt --recipient your.email@example.com \
  --recipient test@example.com multi.txt

# Decrypt with your key
gpg --decrypt multi.txt.gpg
```

### Challenge 2: Batch Encryption

```bash
# Create multiple files
for i in {1..5}; do
    echo "Secret message $i" > file$i.txt
done

# Encrypt all files
for file in file*.txt; do
    gpg --encrypt --recipient your.email@example.com "$file"
done

# Verify all encrypted files exist
ls -la file*.gpg
```

### Challenge 3: Key Import/Export Simulation

```bash
# Export your public key
gpg --export --armor your.email@example.com > my_public_key.asc

# Delete your public key from keyring (simulation only!)
gpg --delete-keys your.email@example.com

# Re-import your public key
gpg --import my_public_key.asc

# List keys to verify import
gpg --list-keys
```

## Verification Checklist

- [ ] Successfully generated a GPG key pair
- [ ] Listed public and secret keys
- [ ] Encrypted a file using your public key
- [ ] Decrypted a file using your private key
- [ ] Created ASCII armored encrypted file
- [ ] Exported your public key
- [ ] Performed symmetric encryption
- [ ] Generated revocation certificate
- [ ] Completed at least one challenge

## Key Takeaways

1. **Public key encrypts, private key decrypts**
2. **Always protect your private key with a strong passphrase**
3. **Binary (.gpg) vs ASCII armor (.asc) formats**
4. **Revocation certificates are crucial for key compromise**
5. **Key IDs and fingerprints uniquely identify keys**

## Common Issues and Solutions

### Issue: "gpg: decryption failed: No secret key"
**Solution:** You're trying to decrypt a file encrypted for someone else's public key, or your private key is not in the keyring.

### Issue: "gpg: [don't know]: invalid packet"
**Solution:** The file is corrupted or not a GPG encrypted file.

### Issue: Forgot passphrase
**Solution:** Without the passphrase, you cannot access the private key. This is why revocation certificates are important.

## Next Steps

Proceed to:
- Lab 2: GPG Digital Signatures
- Lab 3: Key Server Operations
- Lab 4: Web of Trust

## Additional Resources

- [GPG Manual](https://gnupg.org/gph/en/manual.html)
- [GPG Quick Start Guide](https://www.gnupg.org/gph/en/manual/c14.html)
- [Email Self-Defense Guide](https://emailselfdefense.fsf.org/)

