# Directory Structure

This document provides an overview of the cryptography-and-pki directory organization.

## 📁 Directory Tree

```
cryptography-and-pki/
│
├── README.md                          # Main entry point with navigation
├── DIRECTORY_STRUCTURE.md             # This file - directory overview
│
├── 📚 Core Reference Files
│   ├── crypto_algorithms.md           # Algorithm reference (2025 edition)
│   ├── crypto_tools.md                # 100+ cryptography tools
│   ├── crypto_frameworks.md           # Multi-language crypto libraries
│   ├── cert_openssl.md                # OpenSSL certificate operations
│   ├── gpg_how_to.md                  # Complete GPG guide
│   └── disk_encryption.md             # Disk and data encryption guide
│
├── 📖 tutorials/                      # In-depth guides
│   ├── pki-fundamentals.md            # PKI complete guide
│   ├── tls-ssl-guide.md               # TLS/SSL practical configuration
│   ├── code-signing-guide.md          # Code signing for all platforms
│   └── post-quantum-migration.md      # PQC migration strategy
│
├── 🧪 labs/                           # Hands-on exercises
│   ├── README.md                      # Lab overview and learning paths
│   ├── lab-01-gpg-basics.md           # GPG key generation and encryption
│   └── lab-02-openssl-certificates.md # OpenSSL certificate operations
│
├── ⚡ quick-reference/                # Cheat sheets
│   ├── gpg-cheatsheet.md              # GPG command reference
│   ├── openssl-cheatsheet.md          # OpenSSL command reference
│   └── crypto-algorithms-reference.md # Algorithm selection guide
│
└── 🎯 challenges/                     # Cryptography puzzles
    ├── README.md                      # Challenge overview
    ├── 01_Classic_Caesar_Cipher.md
    ├── 02_Diffie_Hellman_Key_Exchange.md
    ├── 03_Digital_Signature_Forgery.md
    ├── 04_Classic_Vigenere_Cipher.md
    ├── 05_Implement_Diffie_Hellman_Key_Exchange.md
    ├── 06_Digital_Signature_Forgery_Advanced.md
    ├── 07_Frequency_Analysis_Attack_Substitution.md
    ├── 08_Elliptic_Curve_Key_Pair_Generation.md
    └── 09_Attack_on_Weak_RSA_Modulus.md
```

## 📚 Core Reference Files

### crypto_algorithms.md
**Purpose:** Essential 2025 cryptography algorithm reference  
**Content:**
- Current standards (ML-KEM, ML-DSA, SLH-DSA, FALCON)
- Deprecated algorithms (RSA, ECC, Diffie-Hellman)
- Symmetric crypto recommendations
- Post-quantum migration guidance

**Use When:** Selecting algorithms for new projects, understanding quantum threats

---

### crypto_tools.md
**Purpose:** Comprehensive toolkit catalog  
**Content:**
- Hash analysis tools
- SSL/TLS testing utilities
- RSA analysis tools
- Encryption testing software
- Steganography tools
- Side-channel attack tools

**Use When:** Performing security assessments, penetration testing, cryptanalysis

---

### crypto_frameworks.md
**Purpose:** Multi-language cryptographic library reference  
**Content:**
- Libraries for 20+ programming languages
- C/C++, Python, JavaScript, Java, Go implementations
- Production-ready crypto frameworks
- Language-specific best practices

**Use When:** Implementing cryptography in applications

---

### cert_openssl.md
**Purpose:** Traditional certificate management with OpenSSL  
**Content:**
- RSA and ECC certificate generation
- CSR creation
- Self-signed certificates
- Post-quantum certificate examples
- Troubleshooting guide

**Use When:** Working with SSL/TLS certificates, setting up CAs

---

### gpg_how_to.md
**Purpose:** Complete GPG operations guide  
**Content:**
- Key generation and management
- File encryption/decryption
- Digital signatures
- Key server operations
- Web of trust
- Backup and recovery

**Use When:** Implementing email encryption, securing files, managing GPG keys

---

### disk_encryption.md
**Purpose:** Comprehensive disk and data encryption  
**Content:**
- Full disk encryption (VeraCrypt, LUKS)
- File-level encryption (cryptomator, EncFS)
- Mobile device encryption
- Cloud storage encryption
- Enterprise key management
- Post-quantum options

**Use When:** Protecting data at rest, securing storage

---

## 📖 Tutorials

### pki-fundamentals.md
**Purpose:** Complete PKI infrastructure guide  
**Content:**
- PKI components and architecture
- Certificate chains and trust models
- CA operations (Root, Intermediate, Issuing)
- Certificate lifecycle management
- Deployment models
- Security best practices

**Use When:** Building PKI infrastructure, understanding trust models

---

### tls-ssl-guide.md
**Purpose:** Practical TLS/SSL configuration  
**Content:**
- TLS 1.2 & 1.3 protocol details
- Server configuration (Apache, Nginx, HAProxy)
- Cipher suite selection
- Performance optimization
- Testing and validation
- Security headers

**Use When:** Securing web servers, implementing HTTPS

---

### code-signing-guide.md
**Purpose:** Software authentication and signing  
**Content:**
- Platform-specific signing (Windows, macOS, Linux, Android, iOS, Docker)
- Certificate management
- Timestamping
- Security best practices
- Verification and validation

**Use When:** Distributing software, implementing CI/CD signing

---

### post-quantum-migration.md
**Purpose:** Future-proof cryptography strategy  
**Content:**
- Quantum threat analysis
- NIST post-quantum standards
- Migration strategy (assessment, planning, implementation)
- Hybrid approaches
- Implementation examples (Python, C, Go, Java)
- Timeline and roadmap

**Use When:** Planning long-term security strategy, implementing PQC

---

## 🧪 Labs

### Lab Structure
Each lab includes:
- Clear objectives
- Prerequisites
- Step-by-step instructions
- Hands-on challenges
- Verification checklists
- Troubleshooting
- Key takeaways

### Available Labs

#### Beginner (30-60 minutes)
- **lab-01-gpg-basics.md**: GPG key generation and file encryption
- **lab-02-openssl-certificates.md**: Private keys, CSRs, certificates

#### Intermediate (45-90 minutes)
- Setting Up a Local CA
- TLS/SSL Configuration
- Code Signing
- GPG Web of Trust

#### Advanced (60-120+ minutes)
- Certificate Revocation (CRL/OCSP)
- Post-Quantum Cryptography Basics
- Complete PKI Infrastructure

**Use When:** Learning through hands-on practice, skill building

---

## ⚡ Quick Reference

### gpg-cheatsheet.md
**Content:**
- Key management commands
- Encryption/decryption
- Digital signatures
- Trust management
- Key servers
- Batch operations
- Configuration tips

**Use When:** Need quick GPG command reference

---

### openssl-cheatsheet.md
**Content:**
- Key generation
- CSR creation
- Certificate operations
- TLS testing
- Format conversions
- Common one-liners
- Troubleshooting

**Use When:** Need quick OpenSSL command reference

---

### crypto-algorithms-reference.md
**Content:**
- Algorithm status guide (recommended, transitional, deprecated)
- Symmetric encryption algorithms
- Hash functions
- Public key cryptography
- Post-quantum algorithms
- Security levels
- Selection guide

**Use When:** Choosing algorithms, understanding security levels

---

## 🎯 Challenges

### Challenge Levels
- **Beginner (🟢):** Classical ciphers, basic techniques
- **Intermediate (🟡):** Key exchange, cryptanalysis
- **Advanced (🔴):** Attacks, forgery, advanced techniques

### Available Challenges
1. Caesar Cipher (🟢)
2. Diffie-Hellman Key Exchange (🟡)
3. Digital Signature Forgery Basic (🔴)
4. Vigenère Cipher (🟢)
5. Implement Diffie-Hellman (🟡)
6. Digital Signature Forgery Advanced (🔴)
7. Frequency Analysis (🟡)
8. Elliptic Curve Key Generation (🟡)
9. RSA Attack (🔴)

**Use When:** Learning through practice, building cryptanalysis skills

---

## 🎓 Recommended Navigation Paths

### For Beginners
```
1. Start: README.md
2. Read: crypto_algorithms.md
3. Lab: lab-01-gpg-basics.md
4. Challenge: 01_Classic_Caesar_Cipher.md
5. Reference: quick-reference/ as needed
```

### For Web Developers
```
1. Read: tutorials/pki-fundamentals.md
2. Read: tutorials/tls-ssl-guide.md
3. Lab: lab-02-openssl-certificates.md
4. Reference: openssl-cheatsheet.md
5. Implement: Production HTTPS
```

### For Security Professionals
```
1. Read: tutorials/post-quantum-migration.md
2. Explore: crypto_tools.md
3. Complete: All advanced challenges
4. Study: crypto_frameworks.md
5. Plan: PQC migration
```

### For DevOps Engineers
```
1. Read: tutorials/code-signing-guide.md
2. Lab: Code Signing
3. Read: cert_openssl.md
4. Implement: Automated signing pipeline
5. Reference: quick-reference/ as needed
```

---

## 📊 Content Statistics

- **Core Reference Files:** 6 comprehensive guides
- **Tutorials:** 4 in-depth tutorials
- **Labs:** 2+ hands-on laboratories
- **Quick Reference:** 3 cheat sheets
- **Challenges:** 9 cryptography puzzles
- **Total Documentation:** ~75,000+ words of content

---

## 🔄 Update Policy

This directory is maintained with:
- Current cryptographic standards
- Post-quantum cryptography focus
- Regular updates for emerging threats
- Community contributions welcome
- Focus on practical, hands-on learning

---

## 📝 Document Conventions

### File Naming
- Descriptive names with hyphens
- Markdown (.md) for documentation
- Lowercase for directories

### Content Structure
- Clear headings and navigation
- Code examples with syntax highlighting
- Security warnings clearly marked
- Cross-references between documents

### Symbols Used
- ✅ Recommended/Current standard
- ⚠️ Transitional/Plan to migrate
- ❌ Deprecated/Do not use
- 🔮 Post-Quantum/Future-proof

---

## 🔗 Quick Links

- **[Main README](README.md)** - Start here
- **[Lab Overview](labs/README.md)** - Hands-on learning
- **[Challenge Overview](challenges/README.md)** - Cryptography puzzles
- **[Algorithm Reference](crypto_algorithms.md)** - Current standards
- **[PQC Migration](tutorials/post-quantum-migration.md)** - Future-proof strategy

---

**Last Updated:** 2025  
**Maintained by:** The Art of Hacking Community

