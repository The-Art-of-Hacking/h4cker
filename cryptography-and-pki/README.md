# Cryptography and PKI Resources

> **Comprehensive collection of cryptography and Public Key Infrastructure (PKI) materials, tools, tutorials, and hands-on labs for security professionals, developers, and enthusiasts.**

## 🎯 Quick Navigation

### 👨‍🏫 Getting Started
- [**Core Resources**](#-core-resources) - Essential cryptography foundations
- [**Practical Guides**](#-practical-guides) - Hands-on tutorials and guides
- [**Hands-On Labs**](labs/) - Interactive learning exercises
- [**Quick Reference**](#-quick-reference) - Cheat sheets and command references

### 🔐 By Topic
- [Cryptographic Algorithms](#cryptographic-algorithms) - Current standards and post-quantum migration
- [PKI & Certificates](#pki--certificate-management) - Certificate operations and CA setup
- [TLS/SSL](#tlsssl-configuration) - Secure communications setup
- [Code Signing](#code-signing) - Software authentication and verification
- [GPG/PGP](#gpg-encryption) - Email and file encryption
- [Post-Quantum Cryptography](#post-quantum-cryptography) - Future-proof cryptography

### ⚡ By Skill Level
- [**Beginner**](#beginner-resources) - New to cryptography
- [**Intermediate**](#intermediate-resources) - Familiar with basics
- [**Advanced**](#advanced-resources) - Deep expertise

---

## 📚 Core Resources

### Cryptographic Algorithms
**[crypto_algorithms.md](crypto_algorithms.md)** - Essential 2025 cryptography reference

**What's Inside:**
- ✅ Current Standards: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FALCON
- ⚠️ Deprecated Algorithms: RSA, ECC/ECDSA, Diffie-Hellman (quantum-vulnerable)
- 🔒 Symmetric Crypto: AES-256, SHA-2/SHA-3 recommendations
- 🚀 Migration Guidance: NIST post-quantum cryptography transition strategies

**Quick Facts:**
- RSA/ECC are deprecated due to quantum vulnerability
- AES-256 and SHA-512 recommended minimum
- Begin PQC migration planning now

### Cryptographic Tools
**[crypto_tools.md](crypto_tools.md)** - Comprehensive toolkit featuring 100+ specialized tools

**Categories:**
- 🔍 Hash Analysis: hashid, hashcat, john, omnihash, hash-extender
- 🔐 SSL/TLS Testing: sslscan, testssl.sh, ssllabs-scan, cipherscan
- 🔑 RSA Analysis: rsactftool, rsatool, rshack, x-rsa
- 💾 Encryption Testing: veracrypt, dislocker, bruteforce-luks
- 🖼️ Steganography: outguess, openstego, snow
- ⚡ Side-Channel Attacks: daredevil, jeangrey, pacumen

**Perfect For:**
- Penetration testing
- Security assessments
- Cryptanalysis
- Research and education

### Cryptographic Frameworks
**[crypto_frameworks.md](crypto_frameworks.md)** - Multi-language crypto libraries

**Coverage:**
- C/C++: OpenSSL, libsodium, Botan, wolfSSL, monocypher
- Python: cryptography, pycryptodome, pynacl, bcrypt
- JavaScript: crypto-js, forge, libsodium.js, noble-crypto
- Java: Bouncy Castle, Google Tink, Apache Shiro
- Go: dedis/crypto, gocrypto, goThemis
- **Plus 15+ other languages** with production-ready implementations

---

## 🛠️ Practical Guides

### PKI & Certificate Management
**[cert_openssl.md](cert_openssl.md)** | **[tutorials/pki-fundamentals.md](tutorials/pki-fundamentals.md)**

**Traditional Operations:**
- 🔑 Private Key Generation: RSA and ECC key creation
- 📜 Certificate Signing Requests (CSR): Proper CSR generation
- 🎫 Self-Signed Certificates: Testing environment certificates
- ⛓️ Certificate Chains: Trust hierarchy and validation
- ✅ Certificate Verification: Validation procedures

**PKI Infrastructure:**
- Certificate Authority setup (Root, Intermediate, Issuing)
- Trust models (Hierarchical, Web of Trust, Bridge CA)
- Certificate lifecycle management
- Enterprise deployment strategies
- Revocation handling (CRL, OCSP)

**Best Practices:**
- ⚠️ RSA/ECC quantum vulnerability warnings
- Hybrid approaches for transition
- Certificate policy and practice statements
- Security and compliance considerations

### TLS/SSL Configuration
**[tutorials/tls-ssl-guide.md](tutorials/tls-ssl-guide.md)**

**Complete Coverage:**
- 📖 TLS 1.2 & TLS 1.3 protocol details
- 🔧 Apache, Nginx, HAProxy configuration
- 🎯 Modern cipher suite selection
- ⚡ Performance optimization (HTTP/2, HTTP/3, OCSP stapling)
- 🔒 Security headers (HSTS, CSP, X-Frame-Options)
- 🧪 Testing tools (SSL Labs, testssl.sh, OpenSSL s_client)

**Configurations For:**
- Web servers (Apache, Nginx)
- Load balancers (HAProxy)
- Node.js applications
- Various platforms and frameworks

### GPG Encryption
**[gpg_how_to.md](gpg_how_to.md)**

**Complete GPG Tutorial:**
- 🔑 Key Generation: Full GPG key pair creation
- 📁 File Encryption/Decryption: Practical examples
- 🌐 Key Server Operations: Publishing and retrieving keys
- ✍️ Digital Signatures: Creating and verifying signatures
- 🤝 Web of Trust: Key signing and trust management
- 💾 Backup & Recovery: Secure key backup procedures

**Advanced Topics:**
- Subkey management
- Trust levels and certification
- Revocation certificates
- Hardware token integration
- Batch operations and automation

### Disk Encryption
**[disk_encryption.md](disk_encryption.md)**

**Comprehensive Coverage:**
- 💾 Full Disk Encryption: VeraCrypt, LUKS, BitLocker alternatives
- 📂 File-Level Encryption: cryptomator, EncFS, git-crypt, sops
- 📱 Mobile Device Encryption: iOS and Android security
- ☁️ Cloud Storage Encryption: Zero-knowledge solutions
- 🔑 Enterprise Key Management: HSM, AWS KMS, Azure Key Vault, HashiCorp Vault
- 🔮 Post-Quantum Options: Future-proofing encryption

**Platform Coverage:**
- Linux (LUKS, EncFS)
- Windows (VeraCrypt, BitLocker)
- macOS (FileVault)
- Cross-platform solutions

### Code Signing
**[tutorials/code-signing-guide.md](tutorials/code-signing-guide.md)**

**Platform-Specific Signing:**
- 🪟 Windows (Authenticode, SignTool)
- 🍎 macOS (Developer ID, Notarization)
- 🐧 Linux (AppImage, RPM, DEB)
- 🤖 Android (APK, AAB signing)
- 🍏 iOS (Code signing, provisioning)
- 🐋 Docker (Content Trust, Cosign, Notary)

**Certificate Management:**
- Obtaining code signing certificates
- EV vs standard certificates
- HSM and hardware token integration
- Certificate lifecycle and renewal

**Best Practices:**
- Private key protection
- Automated signing pipelines
- Timestamping for long-term validity
- Build reproducibility

### Post-Quantum Cryptography
**[tutorials/post-quantum-migration.md](tutorials/post-quantum-migration.md)**

**Migration Strategy:**
- 🎯 Assessment: Inventory and threat analysis
- 📋 Planning: Prioritization and approach selection
- 🚀 Implementation: Phased deployment
- ✅ Validation: Testing and verification

**NIST Standards:**
- ML-KEM (CRYSTALS-Kyber) - Key Encapsulation - FIPS 203
- ML-DSA (CRYSTALS-Dilithium) - Digital Signatures - FIPS 204
- SLH-DSA (SPHINCS+) - Hash-Based Signatures - FIPS 205

**Implementation:**
- Python with liboqs
- C with liboqs
- Go with circl
- Java with Bouncy Castle PQC
- Hybrid approaches (classical + PQC)

**Timeline:**
- 2025: Begin migration planning (NOW)
- 2026-2027: Migrate high-priority systems
- 2028-2029: Widespread adoption
- 2030+: Complete infrastructure migration

---

## 🎓 Hands-On Labs

### Lab Series
**[labs/](labs/)** - Progressive skill-building from beginner to advanced

#### Beginner Labs (30-60 minutes each)
1. **[GPG Basics](labs/lab-01-gpg-basics.md)** - Key generation and file encryption
2. **[OpenSSL Certificates](labs/lab-02-openssl-certificates.md)** - CSRs, certificates, chains

#### Intermediate Labs (45-90 minutes each)
3. **Setting Up a Local CA** - Certificate authority operations
4. **TLS/SSL Configuration** - Web server security
5. **Code Signing** - Software authentication
6. **GPG Web of Trust** - Key signing and validation

#### Advanced Labs (60-120+ minutes each)
7. **Certificate Revocation** - CRL and OCSP setup
8. **Post-Quantum Cryptography** - Future-proof implementations
9. **Complete PKI Infrastructure** - Enterprise deployment

**Each Lab Includes:**
- Clear objectives and prerequisites
- Step-by-step instructions
- Hands-on challenges
- Verification checklists
- Troubleshooting guidance
- Key takeaways

---

## ⚡ Quick Reference

### Cheat Sheets
**[quick-reference/](quick-reference/)**

- **[GPG Cheat Sheet](quick-reference/gpg-cheatsheet.md)** - Essential GPG commands
- **[OpenSSL Cheat Sheet](quick-reference/openssl-cheatsheet.md)** - OpenSSL command reference
- **[Crypto Algorithms Reference](quick-reference/crypto-algorithms-reference.md)** - Algorithm selection guide

**Quick Access:**
- Common command patterns
- One-liner solutions
- Configuration templates
- Troubleshooting commands
- Best practices summaries

---

## 🏆 Cryptography Challenges

### Challenge Series
**[challenges/](challenges/)** - Hands-on cryptography puzzles

**Difficulty Levels:**
- **Beginner**: Caesar Cipher, Vigenère Cipher
- **Intermediate**: Diffie-Hellman, Frequency Analysis, Elliptic Curve Cryptography
- **Advanced**: RSA Attacks, Digital Signature Forgery

**What You'll Learn:**
- Classical cryptography techniques
- Public key cryptography fundamentals
- Cryptographic attacks and weaknesses
- Key exchange protocols
- Digital signature schemes

**[Start with Challenge 1 →](challenges/01_Classic_Caesar_Cipher.md)**

---

## 📊 Learning Paths

### Path 1: PKI & Web Security (4-6 weeks)
**For:** Web developers, system administrators

```
Week 1-2: OpenSSL Basics
├─ Read: cert_openssl.md
├─ Lab: OpenSSL Certificates
└─ Complete: Challenges 1-3

Week 3-4: PKI Infrastructure
├─ Read: tutorials/pki-fundamentals.md
├─ Lab: Setting Up Local CA
└─ Lab: Certificate Revocation

Week 5-6: TLS Configuration
├─ Read: tutorials/tls-ssl-guide.md
├─ Lab: TLS/SSL Configuration
└─ Deploy: Production-ready HTTPS
```

### Path 2: Secure Communications (3-4 weeks)
**For:** Privacy advocates, secure communication needs

```
Week 1: GPG Fundamentals
├─ Read: gpg_how_to.md
├─ Lab: GPG Basics
└─ Setup: Email encryption

Week 2: Web of Trust
├─ Lab: GPG Web of Trust
├─ Practice: Key signing
└─ Join: Key signing party

Week 3-4: Advanced Operations
├─ Lab: GPG automation
├─ Setup: Encrypted backups
└─ Implement: Secure workflows
```

### Path 3: Post-Quantum Preparation (6-8 weeks)
**For:** Security engineers, researchers

```
Week 1-2: Current State
├─ Read: crypto_algorithms.md
├─ Study: Quantum threat timeline
└─ Assessment: Current infrastructure

Week 3-4: PQC Standards
├─ Read: tutorials/post-quantum-migration.md
├─ Study: ML-KEM, ML-DSA, SLH-DSA
└─ Lab: PQC Basics

Week 5-6: Hybrid Implementation
├─ Implement: Hybrid TLS
├─ Test: Interoperability
└─ Deploy: Pilot systems

Week 7-8: Migration Planning
├─ Create: Migration roadmap
├─ Prioritize: Critical systems
└─ Plan: Full deployment
```

### Path 4: Software Security (4-5 weeks)
**For:** Software developers, DevOps engineers

```
Week 1: Code Signing Basics
├─ Read: tutorials/code-signing-guide.md
├─ Obtain: Code signing certificate
└─ Lab: Sign first application

Week 2-3: Platform-Specific Signing
├─ Windows: Authenticode signing
├─ macOS: Developer ID & Notarization
├─ Linux: GPG package signing
└─ Container: Docker image signing

Week 4-5: CI/CD Integration
├─ Automate: Signing pipeline
├─ Implement: Key management
└─ Deploy: Signed releases
```

---

## 🎯 Resources by Skill Level

### Beginner Resources
**New to cryptography? Start here:**

1. **Foundations**
   - Read: [crypto_algorithms.md](crypto_algorithms.md) - Overview of algorithms
   - Complete: [Challenge 1: Caesar Cipher](challenges/01_Classic_Caesar_Cipher.md)
   
2. **Practical Skills**
   - Lab: [GPG Basics](labs/lab-01-gpg-basics.md)
   - Lab: [OpenSSL Certificates](labs/lab-02-openssl-certificates.md)
   - Reference: [GPG Cheat Sheet](quick-reference/gpg-cheatsheet.md)

3. **Next Steps**
   - Read: [gpg_how_to.md](gpg_how_to.md)
   - Complete: Challenges 1-4
   - Practice: Encrypt and sign files daily

### Intermediate Resources
**Familiar with basics? Level up:**

1. **Infrastructure**
   - Read: [tutorials/pki-fundamentals.md](tutorials/pki-fundamentals.md)
   - Read: [tutorials/tls-ssl-guide.md](tutorials/tls-ssl-guide.md)
   - Lab: Setting Up Local CA

2. **Advanced Operations**
   - Read: [tutorials/code-signing-guide.md](tutorials/code-signing-guide.md)
   - Lab: TLS/SSL Configuration
   - Complete: Challenges 5-7

3. **Tools & Automation**
   - Explore: [crypto_tools.md](crypto_tools.md)
   - Reference: [OpenSSL Cheat Sheet](quick-reference/openssl-cheatsheet.md)
   - Automate: Common cryptographic tasks

### Advanced Resources
**Ready for expert topics:**

1. **Enterprise PKI**
   - Lab: Complete PKI Infrastructure
   - Lab: Certificate Revocation (CRL/OCSP)
   - Design: Multi-tier CA architecture

2. **Post-Quantum Cryptography**
   - Read: [tutorials/post-quantum-migration.md](tutorials/post-quantum-migration.md)
   - Lab: PQC Basics
   - Implement: Hybrid cryptography
   - Plan: PQC migration strategy

3. **Security Research**
   - Complete: Challenges 8-9 (Advanced)
   - Explore: Side-channel attacks
   - Contribute: Open source crypto projects
   - Research: Emerging threats

---

## ⚠️ Security Considerations

### Critical Security Notices

**Quantum Threat Timeline:**
- ⚠️ **2025-2030**: Potential quantum computers capable of breaking RSA/ECC
- 🚨 **"Harvest Now, Decrypt Later"**: Adversaries collecting encrypted data now
- 📅 **Migration Deadline**: Begin PQC transition immediately

**Deprecated Algorithms (Do Not Use):**
- ❌ RSA (all key sizes) - Quantum vulnerable
- ❌ ECC/ECDSA - Quantum vulnerable  
- ❌ Diffie-Hellman - Quantum vulnerable
- ❌ AES-128 - Insufficient for post-quantum (64-bit effective security)
- ❌ SHA-1 - Collision attacks
- ❌ MD5 - Completely broken

**Current Recommendations:**
- ✅ AES-256 minimum for symmetric encryption
- ✅ SHA-512 minimum for hashing
- ✅ ML-KEM (Kyber) for key exchange (post-quantum)
- ✅ ML-DSA (Dilithium) for signatures (post-quantum)
- ✅ Hybrid approaches during transition
- ✅ Always use established libraries (never roll your own crypto)

### Best Practices

**Key Management:**
- Use strong, unique passphrases
- Store keys in HSMs when possible
- Implement proper key rotation
- Maintain secure backups
- Never commit keys to version control

**Certificate Management:**
- Set appropriate validity periods (1-2 years max)
- Implement automated renewal
- Monitor expiration dates
- Maintain revocation procedures
- Use certificate transparency

**Implementation:**
- Always use established, audited libraries
- Keep cryptographic libraries updated
- Follow NIST and industry standards
- Implement proper error handling
- Log security events appropriately

---

## 🔗 Additional Resources

### Official Standards
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [RFC 5280 - X.509 PKI Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)

### Community & Learning
- [Cryptography Stack Exchange](https://crypto.stackexchange.com/)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SSL Labs](https://www.ssllabs.com/)

### Books & Documentation
- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
- [Cryptography Engineering - Ferguson, Schneier, Kohno](https://www.schneier.com/books/cryptography-engineering/)
- [Serious Cryptography - Jean-Philippe Aumasson](https://nostarch.com/seriouscrypto)
- [OpenSSL Cookbook - Ivan Ristić](https://www.feistyduck.com/books/openssl-cookbook/)

---

## 🤝 Contributing

This is a living collection that grows and evolves with the field of cryptography. Contributions are welcome!

**Ways to Contribute:**
- 📝 Submit corrections or improvements
- 💡 Add new examples and use cases
- 🔬 Share research findings
- 📚 Create additional tutorials
- 🧪 Develop new lab exercises
- 🐛 Report issues or broken links

---

## 📄 License

This collection is provided for educational and research purposes. Always consult relevant laws and regulations when implementing cryptography in production systems.

---

## 🎓 About This Collection

This comprehensive resource is designed for:
- Security professionals building secure systems
- Developers implementing cryptography
- Students learning cryptographic concepts
- Researchers studying cryptanalysis
- Anyone interested in secure communications

**Last Updated**: 2025  
**Maintainer**: The Art of Hacking  
**Focus**: Modern cryptography with post-quantum preparation

---

## 🚀 Get Started Now

**New to cryptography?**
1. Start with [crypto_algorithms.md](crypto_algorithms.md)
2. Complete [Lab 1: GPG Basics](labs/lab-01-gpg-basics.md)
3. Try [Challenge 1: Caesar Cipher](challenges/01_Classic_Caesar_Cipher.md)

**Building a web application?**
1. Read [tutorials/tls-ssl-guide.md](tutorials/tls-ssl-guide.md)
2. Follow [tutorials/pki-fundamentals.md](tutorials/pki-fundamentals.md)
3. Use [quick-reference/openssl-cheatsheet.md](quick-reference/openssl-cheatsheet.md)

**Preparing for post-quantum?**
1. Assess your infrastructure using [crypto_algorithms.md](crypto_algorithms.md)
2. Study [tutorials/post-quantum-migration.md](tutorials/post-quantum-migration.md)
3. Test PQC implementations in lab environments

**Happy learning! 🔐**
