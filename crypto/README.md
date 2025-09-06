# Cryptography Security Resources

This comprehensive collection provides materials, tools, and practical resources for understanding and implementing cryptography in cybersecurity contexts. The resources span from theoretical foundations to hands-on challenges and real-world applications.

## 📚 Core Resources

### [🔐 Cryptographic Algorithms](crypto_algorithms.md)
**Essential 2025 cryptography reference** covering current standards and post-quantum cryptography migration guidance:
- **Current Standards**: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FALCON
- **Deprecated Algorithms**: RSA, ECC/ECDSA, Diffie-Hellman (quantum-vulnerable)
- **Symmetric Crypto**: AES-256, SHA-2/SHA-3 recommendations
- **Migration Guidance**: NIST post-quantum cryptography transition strategies

### [🛠️ Cryptographic Tools](crypto_tools.md)
**Comprehensive toolkit** for cryptographic testing and analysis featuring 100+ specialized tools:
- **Hash Analysis**: hashid, hashcat, john, omnihash, hash-extender
- **SSL/TLS Testing**: sslscan, testssl.sh, ssllabs-scan, cipherscan
- **RSA Analysis**: rsactftool, rsatool, rshack, x-rsa
- **Encryption Testing**: veracrypt, dislocker, bruteforce-luks
- **Steganography**: outguess, openstego, snow
- **Side-Channel Attacks**: daredevil, jeangrey, pacumen

### [🏗️ Cryptographic Frameworks](crypto_frameworks.md)
**Multi-language crypto libraries** organized by programming language:
- **C/C++**: OpenSSL, libsodium, Botan, wolfSSL, monocypher
- **Python**: cryptography, pycryptodome, pynacl, bcrypt
- **JavaScript**: crypto-js, forge, libsodium.js, noble-crypto
- **Java**: Bouncy Castle, Google Tink, Apache Shiro
- **Go**: dedis/crypto, gocrypto, goThemis
- **And 15+ other languages** with production-ready implementations

## 🔧 Practical Guides

### [📜 Certificate Management with OpenSSL](cert_openssl.md)
**Step-by-step OpenSSL guide** for certificate operations:
- **Private Key Generation**: RSA key creation with AES-256 encryption
- **Certificate Signing Requests (CSR)**: Proper CSR generation and submission
- **Self-Signed Certificates**: Creating certificates for testing environments
- **Best Practices**: Security considerations and common pitfalls

### [🔒 GPG Encryption Guide](gpg_how_to.md)
**Complete GPG tutorial** for file encryption and key management:
- **Key Generation**: Full GPG key pair creation with proper parameters
- **File Encryption/Decryption**: Practical examples with recipient specification
- **Key Management**: Best practices for key storage and distribution
- **Security Considerations**: Passphrase protection and key expiry

### [💾 Disk Encryption Solutions](disk_encryption.md)
**Modern disk encryption tools** for data protection:
- **Full Disk Encryption**: VeraCrypt, LUKS, BitLocker alternatives
- **File-Level Encryption**: cryptomator, git-crypt, sops
- **Cloud Storage Security**: Encrypted backup solutions
- **Key Management**: Secure key storage and recovery options

## 🎯 Hands-On Learning

### [🏆 Cryptography Challenges](challenges/)
**Progressive skill-building challenges** from beginner to advanced:

#### **Beginner Level**
- **[Caesar Cipher](challenges/01_Classic_Caesar_Cipher.md)**: Classical substitution cipher decryption
- **[Vigenère Cipher](challenges/04_Classic_Vigenere_Cipher.md)**: Polyalphabetic cipher with known key

#### **Intermediate Level**
- **[Diffie-Hellman Key Exchange](challenges/02_Diffie_Hellman_Key_Exchange.md)**: Key exchange simulation
- **[Frequency Analysis](challenges/07_Frequency_Analysis_Attack_Substitution.md)**: Statistical cryptanalysis
- **[Elliptic Curve Cryptography](challenges/08_Elliptic_Curve_Key_Pair_Generation.md)**: ECC key generation

#### **Advanced Level**
- **[RSA Attacks](challenges/09_Attack_on_Weak_RSA_Modulus.md)**: Exploiting weak RSA parameters
- **[Digital Signature Forgery](challenges/06_Digital_Signature_Forgery_Advanced.md)**: Advanced signature attacks

## 🚨 Security Considerations

⚠️ **Important Security Notes:**
- **Quantum Threat**: RSA, ECC, and DH are deprecated due to quantum vulnerability
- **Migration Required**: Transition to post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)
- **Key Sizes**: Use AES-256 minimum, SHA-256+ for hashing
- **Implementation**: Always use established libraries, never roll your own crypto

## 📖 Additional Learning Resources

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)



