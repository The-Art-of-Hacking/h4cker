# GPG Quick Reference Cheat Sheet

## Key Management

### Generate Keys
```bash
# Interactive full key generation
gpg --full-generate-key

# Quick generation with defaults
gpg --quick-generate-key "Name <email>" rsa4096 encrypt,sign 2y

# Generate ECC key
gpg --quick-generate-key "Name <email>" ed25519 sign 2y
```

### List Keys
```bash
# List public keys
gpg --list-keys
gpg -k

# List secret keys
gpg --list-secret-keys
gpg -K

# Show fingerprints
gpg --fingerprint
gpg --fingerprint KEY_ID
```

### Export Keys
```bash
# Export public key (ASCII)
gpg --export --armor KEY_ID > public.asc
gpg -a --export KEY_ID > public.asc

# Export public key (binary)
gpg --export KEY_ID > public.gpg

# Export secret key
gpg --export-secret-keys --armor KEY_ID > secret.asc

# Export all keys
gpg --export-secret-keys --armor > all-secret.asc
```

### Import Keys
```bash
# Import key
gpg --import key.asc

# Import from keyserver
gpg --recv-keys KEY_ID
gpg --keyserver keys.openpgp.org --recv-keys KEY_ID
```

### Delete Keys
```bash
# Delete public key
gpg --delete-keys KEY_ID

# Delete secret key
gpg --delete-secret-keys KEY_ID

# Delete both
gpg --delete-secret-and-public-keys KEY_ID
```

## Encryption & Decryption

### Encrypt Files
```bash
# Encrypt for recipient
gpg --encrypt --recipient user@example.com file.txt
gpg -e -r user@example.com file.txt

# Encrypt for multiple recipients
gpg -e -r alice@example.com -r bob@example.com file.txt

# Encrypt with ASCII armor
gpg --encrypt --armor -r user@example.com file.txt
gpg -ea -r user@example.com file.txt

# Symmetric encryption (password only)
gpg --symmetric file.txt
gpg -c file.txt
```

### Decrypt Files
```bash
# Decrypt file
gpg --decrypt file.txt.gpg > decrypted.txt
gpg -d file.txt.gpg > decrypted.txt

# Decrypt to stdout
gpg --decrypt file.txt.gpg

# Decrypt with output file
gpg --output decrypted.txt --decrypt file.txt.gpg
gpg -o decrypted.txt -d file.txt.gpg
```

## Digital Signatures

### Sign Files
```bash
# Sign file (embedded signature)
gpg --sign file.txt
gpg -s file.txt

# Detached signature
gpg --detach-sign file.txt
gpg -b file.txt

# ASCII-armored detached signature
gpg --armor --detach-sign file.txt
gpg -ab file.txt

# Clear-sign text file
gpg --clearsign message.txt
```

### Verify Signatures
```bash
# Verify signed file
gpg --verify file.txt.sig
gpg --verify file.txt.sig file.txt

# Verify and extract
gpg --decrypt file.txt.gpg

# Show signature details
gpg --status-fd 1 --verify file.txt.sig
```

## Key Signing & Trust

### Sign Keys
```bash
# Sign a key
gpg --sign-key KEY_ID

# Sign with certification level
gpg --ask-cert-level --sign-key KEY_ID

# Local signature (non-exportable)
gpg --lsign-key KEY_ID
```

### Trust Management
```bash
# Edit key trust
gpg --edit-key KEY_ID
# In prompt: trust

# Export trust database
gpg --export-ownertrust > trust.txt

# Import trust database
gpg --import-ownertrust trust.txt

# Update trust database
gpg --update-trustdb
```

### Key Servers
```bash
# Upload key to keyserver
gpg --send-keys KEY_ID
gpg --keyserver keys.openpgp.org --send-keys KEY_ID

# Search keyserver
gpg --search-keys user@example.com

# Refresh keys from keyserver
gpg --refresh-keys

# Receive key by ID
gpg --recv-keys KEY_ID
```

## Key Editing

### Edit Key
```bash
gpg --edit-key KEY_ID

# Common edit commands:
adduid     # Add user ID
deluid     # Delete user ID
addphoto   # Add photo ID
addkey     # Add subkey
delkey     # Delete subkey
expire     # Change expiration
passwd     # Change passphrase
trust      # Change trust level
sign       # Sign key
lsign      # Local sign
clean      # Remove unusable signatures
save       # Save and exit
quit       # Exit without saving
```

## Revocation

### Generate Revocation Certificate
```bash
# Generate revocation certificate
gpg --gen-revoke KEY_ID > revoke.asc

# Generate with reason
gpg --command-fd 0 --gen-revoke KEY_ID << EOF
y
1
Key compromised
y
EOF
```

### Revoke Key
```bash
# Import revocation certificate
gpg --import revoke.asc

# Upload revocation to keyserver
gpg --send-keys KEY_ID
```

## Batch Operations

### Encrypt Multiple Files
```bash
# Encrypt all .txt files
for file in *.txt; do
    gpg -e -r user@example.com "$file"
done

# Encrypt directory
tar czf - directory/ | gpg -e -r user@example.com > dir.tar.gz.gpg
```

### Decrypt Multiple Files
```bash
# Decrypt all .gpg files
for file in *.gpg; do
    gpg -o "${file%.gpg}" -d "$file"
done

# Decrypt directory
gpg -d dir.tar.gz.gpg | tar xzf -
```

## Configuration

### GPG Configuration File
```bash
# Location: ~/.gnupg/gpg.conf

# Recommended settings:
no-greeting
keyserver hkps://keys.openpgp.org
keyserver-options auto-key-retrieve
personal-digest-preferences SHA512 SHA384 SHA256
personal-cipher-preferences AES256 AES192 AES
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
use-agent
require-cross-certification
no-symkey-cache
throw-keyids
```

### GPG Agent
```bash
# Start agent
gpg-agent --daemon

# Kill agent
gpgconf --kill gpg-agent

# Reload agent
gpg-connect-agent reloadagent /bye
```

## Tips & Tricks

### Useful Flags
```bash
-a, --armor          # ASCII armored output
-e, --encrypt        # Encrypt data
-d, --decrypt        # Decrypt data
-s, --sign           # Make a signature
-b, --detach-sign    # Make detached signature
-c, --symmetric      # Symmetric encryption
-r, --recipient      # Specify recipient
-o, --output         # Specify output file
-v, --verbose        # Verbose mode
-q, --quiet          # Quiet mode
--no-armor           # Binary output
--batch              # Batch mode (no prompts)
```

### Extract Specific Information
```bash
# Get key ID from fingerprint
gpg --list-keys --with-colons | grep "^pub"

# Show key expiration
gpg --list-keys KEY_ID | grep "expires"

# Get key fingerprint only
gpg --fingerprint --with-colons KEY_ID | grep "^fpr" | cut -d: -f10

# List key capabilities
gpg --list-keys --with-colons KEY_ID | grep "^pub\|^sub"
```

### Security Best Practices
```bash
# Generate strong keys
gpg --full-generate-key  # Choose RSA 4096 or ECC

# Always use passphrases
gpg --passwd KEY_ID

# Set expiration dates
gpg --quick-set-expire KEY_ID 2y

# Regular backups
gpg --export-secret-keys -a > backup.asc

# Use hardware tokens
gpg --card-status
```

## Common Tasks Quick Reference

| Task | Command |
|------|---------|
| Generate key | `gpg --full-generate-key` |
| List keys | `gpg -k` / `gpg -K` |
| Export public key | `gpg -a --export KEY_ID > pub.asc` |
| Import key | `gpg --import key.asc` |
| Encrypt file | `gpg -e -r user@example.com file.txt` |
| Decrypt file | `gpg -d file.txt.gpg > file.txt` |
| Sign file | `gpg -ab file.txt` |
| Verify signature | `gpg --verify file.txt.sig file.txt` |
| Upload to keyserver | `gpg --send-keys KEY_ID` |
| Search keyserver | `gpg --search-keys email@example.com` |
| Change passphrase | `gpg --passwd KEY_ID` |
| Set expiration | `gpg --quick-set-expire KEY_ID 2y` |

## Troubleshooting

```bash
# Refresh expired keys
gpg --refresh-keys

# Fix "unusable secret key"
gpg --edit-key KEY_ID
# Then: trust → 5 (ultimate) → save

# Check GPG version
gpg --version

# Debug mode
gpg --debug-level advanced --verbose

# Fix permissions
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

## See Also
- `man gpg` - Full GPG manual
- `man gpg-agent` - GPG agent documentation
- [GnuPG.org](https://gnupg.org) - Official website

