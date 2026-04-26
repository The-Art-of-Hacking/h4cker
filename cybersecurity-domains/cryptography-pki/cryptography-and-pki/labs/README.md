# Cryptography and PKI Hands-On Labs

## Overview

This directory contains practical, hands-on laboratories designed to build your cryptography and PKI skills through real-world exercises. Each lab includes step-by-step instructions, challenges, and verification checklists.

## Lab Structure

Each lab includes:
- **Objectives**: What you'll learn
- **Prerequisites**: Required knowledge and tools
- **Estimated Time**: How long the lab takes
- **Step-by-Step Instructions**: Detailed guidance
- **Challenges**: Advanced exercises to test your skills
- **Verification Checklist**: Ensure you've completed all tasks
- **Key Takeaways**: Important concepts to remember
- **Troubleshooting**: Common issues and solutions

## Available Labs

### Beginner Level

#### Lab 1: GPG Basics - Key Generation and File Encryption
**Duration**: 30-45 minutes  
**Topics**: GPG key generation, file encryption/decryption, key export/import  
**Skills**: Basic public key cryptography operations

#### Lab 2: OpenSSL Certificate Operations
**Duration**: 45-60 minutes  
**Topics**: Private keys, CSRs, self-signed certificates, certificate chains  
**Skills**: Certificate management, PKI basics

#### Lab 3: Symmetric Encryption Fundamentals
**Duration**: 30 minutes  
**Topics**: AES encryption, key management, encryption modes  
**Skills**: Symmetric cryptography, secure file encryption

### Intermediate Level

#### Lab 4: Setting Up a Local Certificate Authority
**Duration**: 60-90 minutes  
**Topics**: CA setup, certificate issuance, chain validation  
**Skills**: PKI infrastructure, certificate lifecycle

#### Lab 5: TLS/SSL Configuration
**Duration**: 60 minutes  
**Topics**: Web server TLS setup, cipher configuration, certificate installation  
**Skills**: Secure communications, web security

#### Lab 6: Code Signing
**Duration**: 45-60 minutes  
**Topics**: Signing executables, scripts, verification  
**Skills**: Software authentication, integrity verification

#### Lab 7: GPG Web of Trust
**Duration**: 45 minutes  
**Topics**: Key signing, trust levels, keyserver operations  
**Skills**: Decentralized trust, key validation

### Advanced Level

#### Lab 8: Certificate Revocation (CRL and OCSP)
**Duration**: 60 minutes  
**Topics**: CRL generation, OCSP responder setup, revocation checking  
**Skills**: Certificate lifecycle, revocation management

#### Lab 9: Post-Quantum Cryptography Basics
**Duration**: 90 minutes  
**Topics**: ML-KEM (Kyber), ML-DSA (Dilithium), hybrid implementations  
**Skills**: Next-generation cryptography

#### Lab 10: Building a Complete PKI Infrastructure
**Duration**: 120+ minutes  
**Topics**: Multi-tier CA, certificate policies, automation  
**Skills**: Enterprise PKI deployment

## Lab Environment Setup

### Required Software

```bash
# Linux (Debian/Ubuntu)
sudo apt update
sudo apt install -y gnupg openssl ca-certificates \
  apache2 nginx git build-essential

# macOS
brew install gnupg openssl apache2 nginx

# Windows
# Install GPG from https://gnupg.org/download/
# Install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
# Or use Chocolatey:
choco install gnupg openssl
```

### Recommended Directory Structure

```bash
mkdir -p ~/crypto-labs/{gpg,ssl,ca,tls,pqc}
cd ~/crypto-labs
```

### Testing Environment

For advanced labs, consider using:
- **Virtual Machines**: VirtualBox, VMware, or cloud instances
- **Containers**: Docker for isolated environments
- **Local Network**: Multiple machines for distributed PKI testing

## Lab Prerequisites

### Knowledge Prerequisites

- Basic command line skills
- Understanding of cryptographic concepts (symmetric vs asymmetric)
- Familiarity with text editors
- Basic networking knowledge (for TLS labs)

### Skill Level Guide

- **Beginner**: No prior cryptography experience needed
- **Intermediate**: Completed beginner labs or equivalent knowledge
- **Advanced**: Solid understanding of PKI and cryptography concepts

## Learning Path

### Path 1: GPG and Email Encryption
1. Lab 1: GPG Basics
2. Lab 7: GPG Web of Trust
3. Bonus: Email encryption setup

### Path 2: Web PKI and TLS
1. Lab 2: OpenSSL Certificate Operations
2. Lab 4: Setting Up a Local CA
3. Lab 5: TLS/SSL Configuration
4. Lab 8: Certificate Revocation

### Path 3: Software Security
1. Lab 2: OpenSSL Certificate Operations
2. Lab 6: Code Signing
3. Lab 8: Certificate Revocation

### Path 4: Post-Quantum Preparation
1. Lab 2: OpenSSL Certificate Operations
2. Lab 9: Post-Quantum Cryptography Basics
3. Bonus: Hybrid TLS implementation

### Path 5: Complete PKI Mastery
1. Complete all beginner labs (1-3)
2. Complete all intermediate labs (4-7)
3. Complete all advanced labs (8-10)

## Tips for Success

### General Tips

1. **Read Thoroughly**: Review entire lab before starting
2. **Take Notes**: Document your findings and issues
3. **Experiment**: Try variations beyond the instructions
4. **Break Things**: Learning from failures is valuable
5. **Ask Questions**: Use the resources section if stuck

### Best Practices

- **Save Your Work**: Keep copies of generated keys and certificates
- **Use Version Control**: Track your configuration changes
- **Document Everything**: Maintain a lab journal
- **Test Thoroughly**: Verify each step before proceeding
- **Security First**: Never use lab keys in production

### Common Pitfalls to Avoid

- ❌ Using lab keys/certificates in production
- ❌ Skipping verification steps
- ❌ Not reading error messages carefully
- ❌ Rushing through without understanding
- ❌ Ignoring security warnings

## Lab Completion Certificate

After completing all labs, you will have demonstrated:

- ✓ GPG key management and encryption
- ✓ PKI certificate operations
- ✓ CA setup and management
- ✓ TLS/SSL configuration
- ✓ Code signing procedures
- ✓ Certificate revocation handling
- ✓ Post-quantum cryptography basics
- ✓ End-to-end PKI infrastructure deployment

## Additional Challenges

### Cross-Lab Challenges

1. **Complete PKI Deployment**: Use skills from multiple labs to build a full PKI
2. **Automated Certificate Management**: Write scripts to automate common tasks
3. **Security Audit**: Analyze and improve lab configurations
4. **Documentation Project**: Create comprehensive PKI documentation
5. **Training Module**: Teach concepts to others using your lab experience

### Real-World Scenarios

1. **Corporate PKI**: Design and implement an enterprise PKI
2. **IoT Device Authentication**: Secure IoT devices with certificates
3. **Secure Email Infrastructure**: Build a complete email encryption system
4. **Code Signing Pipeline**: Integrate code signing into CI/CD
5. **Cloud PKI**: Implement PKI in cloud environment

## Troubleshooting Resources

### Common Issues

1. **Permission Errors**: Check file/directory permissions
2. **Path Issues**: Verify working directory and file locations
3. **Tool Version Mismatches**: Update tools to recommended versions
4. **Configuration Errors**: Double-check syntax and formatting

### Getting Help

- Review lab troubleshooting sections
- Check tool documentation
- Search for error messages
- Consult additional resources
- Join cryptography forums and communities

## Additional Resources

### Documentation
- [GnuPG Manual](https://gnupg.org/gph/en/manual.html)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

### Online Tools
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [ASN.1 Decoder](https://lapo.it/asn1js/)

### Community
- [Cryptography Stack Exchange](https://crypto.stackexchange.com/)
- [/r/crypto](https://reddit.com/r/crypto)
- [IETF Crypto Forum](https://www.ietf.org/mailman/listinfo/crypto-forum)

### Books
- *Applied Cryptography* by Bruce Schneier
- *Cryptography Engineering* by Ferguson, Schneier, and Kohno
- *Serious Cryptography* by Jean-Philippe Aumasson

## Lab Feedback

We value your feedback! After completing labs, consider:
- What worked well?
- What was confusing?
- What additional topics would you like covered?
- How can we improve the labs?

## Next Steps

1. Choose a learning path that matches your goals
2. Set up your lab environment
3. Start with Lab 1 or your chosen starting point
4. Work through labs systematically
5. Complete challenges to reinforce learning
6. Apply skills to real-world scenarios

Happy learning! 🔐

