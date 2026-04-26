# Post-Quantum Cryptography Migration Guide

## Table of Contents
- [Introduction](#introduction)
- [Understanding the Quantum Threat](#understanding-the-quantum-threat)
- [NIST Post-Quantum Standards](#nist-post-quantum-standards)
- [Migration Strategy](#migration-strategy)
- [Hybrid Approaches](#hybrid-approaches)
- [Implementation Examples](#implementation-examples)
- [Testing and Validation](#testing-and-validation)
- [Timeline and Roadmap](#timeline-and-roadmap)

## Introduction

### The Quantum Computing Threat

Quantum computers, when sufficiently powerful, will break current public-key cryptography systems:

**Vulnerable Algorithms:**
- ❌ RSA (all key sizes)
- ❌ Elliptic Curve Cryptography (ECC/ECDSA/ECDH)
- ❌ Diffie-Hellman key exchange
- ❌ DSA (Digital Signature Algorithm)
- ❌ EdDSA (Ed25519)

**Shor's Algorithm**: Quantum algorithm that can factor large numbers and solve discrete logarithm problems efficiently, breaking RSA and ECC.

**Grover's Algorithm**: Quantum algorithm that provides quadratic speedup for brute-force attacks, effectively halving symmetric key strength.

### Timeline

```
2015 ────── NSA announces quantum-resistant crypto initiative
2016 ────── NIST begins PQC standardization process
2022 ────── NIST announces first PQC standards
2024 ────── NIST publishes finalized standards (FIPS 203, 204, 205)
2025 ────── Begin widespread migration (NOW)
2030 ────── Target for significant PQC adoption
2035 ────── Potential quantum threat realization
```

⚠️ **Harvest Now, Decrypt Later**: Adversaries are collecting encrypted data today to decrypt it when quantum computers become available. Long-term sensitive data needs PQC protection NOW.

### Impact Assessment

**High Priority:**
- Long-term sensitive data (medical, financial, government)
- Critical infrastructure
- Long-lived certificates and keys
- Cryptocurrency and blockchain
- Secure communications infrastructure

**Medium Priority:**
- Standard TLS/SSL implementations
- VPN and remote access
- Code signing certificates
- Email encryption

**Lower Priority:**
- Short-lived session keys
- Ephemeral communications
- Time-sensitive data

## Understanding the Quantum Threat

### Shor's Algorithm Impact

```python
# Classical factoring complexity
classical_time = O(exp((64/9 * n)^(1/3) * (log n)^(2/3)))

# Quantum factoring complexity (Shor's algorithm)
quantum_time = O((log n)^3)

# Example: RSA-2048
# Classical: ~300 trillion years
# Quantum: ~8 hours (on sufficiently powerful quantum computer)
```

### Grover's Algorithm Impact

```
Symmetric Key Strength Reduction:
- AES-128 → Effective 64-bit security (INSECURE)
- AES-192 → Effective 96-bit security (MARGINAL)
- AES-256 → Effective 128-bit security (SECURE)

Hash Output Size Reduction:
- SHA-256 → Effective 128-bit collision resistance (SECURE)
- SHA-384 → Effective 192-bit collision resistance (SECURE)
- SHA-512 → Effective 256-bit collision resistance (SECURE)
```

### Quantum Computer Progress

```
Current State (2025):
- IBM Quantum: ~1000+ qubits
- Google Quantum: Willow chip demonstrated error correction
- IonQ: Trapped ion quantum computers
- D-Wave: Quantum annealing systems

Estimated Requirements for Breaking Cryptography:
- RSA-2048: ~20 million qubits (error-corrected)
- ECC-256: ~2330 qubits (error-corrected)

Timeline:
- 2025-2030: Continued development, increasing qubit counts
- 2030-2035: Potentially cryptographically relevant quantum computers
- 2035+: Widespread quantum computing capability
```

## NIST Post-Quantum Standards

### Selected Algorithms

#### 1. ML-KEM (CRYSTALS-Kyber) - FIPS 203

**Purpose**: Key Encapsulation Mechanism (KEM)
**Replacement for**: RSA and ECDH key exchange

**Security Levels:**
- ML-KEM-512: Equivalent to AES-128
- ML-KEM-768: Equivalent to AES-192 (recommended)
- ML-KEM-1024: Equivalent to AES-256

**Performance:**
```
Key Generation: 0.04 ms
Encapsulation:  0.05 ms
Decapsulation:  0.06 ms
Public Key:     1184 bytes
Ciphertext:     1088 bytes
```

**Use Cases:**
- TLS key exchange
- VPN session establishment
- Secure messaging
- Hybrid encryption

#### 2. ML-DSA (CRYSTALS-Dilithium) - FIPS 204

**Purpose**: Digital Signatures
**Replacement for**: RSA and ECDSA signatures

**Security Levels:**
- ML-DSA-44: Equivalent to AES-128
- ML-DSA-65: Equivalent to AES-192 (recommended)
- ML-DSA-87: Equivalent to AES-256

**Performance:**
```
Key Generation: 0.1 ms
Signing:        0.2 ms
Verification:   0.08 ms
Public Key:     1952 bytes
Signature:      3293 bytes
```

**Use Cases:**
- Certificate signatures
- Code signing
- Document signing
- Blockchain transactions

#### 3. SLH-DSA (SPHINCS+) - FIPS 205

**Purpose**: Stateless Hash-Based Signatures
**Replacement for**: RSA and ECDSA signatures

**Security Levels:**
- SLH-DSA-128s: Fast signing, larger signatures
- SLH-DSA-128f: Smaller signatures, slower signing
- Similar variants for 192 and 256-bit security

**Performance:**
```
Key Generation: 0.5 ms
Signing:        25-50 ms (slower than ML-DSA)
Verification:   1-2 ms
Public Key:     32 bytes
Signature:      8-49 KB (large!)
```

**Use Cases:**
- Long-term signatures
- Firmware signing
- Critical infrastructure
- When conservative security is paramount

#### 4. Additional Candidates

**FALCON**: Selected for standardization
- Compact signatures (~650 bytes)
- Fast operations
- Complex implementation

**BIKE, HQC**: Selected for future standardization
- Code-based cryptography
- Alternative to lattice-based schemes

## Migration Strategy

### Phase 1: Assessment (3-6 months)

```bash
# Inventory cryptographic assets
1. Identify all systems using public-key cryptography
2. Document certificate lifecycles
3. Map data sensitivity and retention
4. Assess quantum threat timeline for your data
```

**Assessment Checklist:**
- [ ] TLS/SSL certificates and implementations
- [ ] VPN and IPsec configurations
- [ ] Code signing certificates
- [ ] SSH keys and configurations
- [ ] Email encryption (S/MIME, PGP)
- [ ] Cryptocurrency and blockchain systems
- [ ] IoT device authentication
- [ ] API authentication
- [ ] Database encryption
- [ ] Backup encryption

### Phase 2: Planning (6-12 months)

```markdown
1. Prioritize systems by:
   - Data sensitivity
   - Threat model
   - Certificate expiration
   - System criticality

2. Select migration approach:
   - Full replacement
   - Hybrid (classical + PQC)
   - Phased migration

3. Develop testing strategy
4. Plan for backward compatibility
5. Budget for increased key sizes
```

### Phase 3: Implementation (12-24 months)

```markdown
1. Update cryptographic libraries
2. Deploy hybrid solutions
3. Update certificates and keys
4. Migrate high-priority systems
5. Update protocols and configurations
```

### Phase 4: Validation (6-12 months)

```markdown
1. Test interoperability
2. Measure performance impact
3. Verify security properties
4. Audit implementations
5. Monitor for issues
```

### Phase 5: Full Migration (2026-2030)

```markdown
1. Complete migration of all systems
2. Deprecate classical algorithms
3. Regular security audits
4. Stay updated on new standards
```

## Hybrid Approaches

### Why Hybrid?

**Benefits:**
- Maintains backward compatibility
- Provides defense-in-depth
- Protects against PQC algorithm breaks
- Enables gradual migration

**Principle**: Security is maintained even if one algorithm is broken.

### Hybrid TLS Implementation

#### Hybrid X.509 Certificates

```bash
# Conceptual structure
Certificate:
    Signature Algorithm: ML-DSA-65 + ECDSA-P256
    Subject Public Key Info:
        Public Key Algorithm: ML-KEM-768 + X25519
        ML-KEM Public Key: [1184 bytes]
        X25519 Public Key: [32 bytes]
    Issuer Signature (ML-DSA-65): [3293 bytes]
    Issuer Signature (ECDSA-P256): [72 bytes]
```

#### Hybrid Key Exchange

```python
# Hybrid KEM: Combine ML-KEM and ECDH
def hybrid_kem_encaps(pk_kem, pk_ecdh):
    # ML-KEM encapsulation
    ct_kem, ss_kem = ml_kem_encaps(pk_kem)
    
    # ECDH key exchange
    ecdh_secret = ecdh_exchange(pk_ecdh)
    
    # Combine shared secrets
    shared_secret = KDF(ss_kem || ecdh_secret)
    
    return (ct_kem, shared_secret)

def hybrid_kem_decaps(sk_kem, sk_ecdh, ct_kem):
    # ML-KEM decapsulation
    ss_kem = ml_kem_decaps(sk_kem, ct_kem)
    
    # ECDH key exchange
    ecdh_secret = ecdh_exchange(sk_ecdh)
    
    # Combine shared secrets
    shared_secret = KDF(ss_kem || ecdh_secret)
    
    return shared_secret
```

### Hybrid OpenSSL Example

```bash
# Install OpenSSL with OQS provider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -B build -S .
cmake --build build
sudo cmake --install build

# Generate hybrid key
openssl genpkey -algorithm p256_kyber512 -out hybrid_key.pem

# Create hybrid certificate request
openssl req -new -key hybrid_key.pem -out hybrid.csr \
  -subj "/CN=Hybrid PQC Test"

# Self-signed hybrid certificate
openssl req -new -x509 -days 365 -key hybrid_key.pem \
  -out hybrid_cert.pem
```

## Implementation Examples

### Python with liboqs

```python
import oqs

# ML-KEM (Kyber) Key Encapsulation
def kyber_example():
    # Create KEM object
    kem = oqs.KeyEncapsulation("Kyber768")
    
    # Generate keypair
    public_key = kem.generate_keypair()
    
    # Encapsulate (sender side)
    ciphertext, shared_secret_sender = kem.encap_secret(public_key)
    
    # Decapsulate (receiver side)
    shared_secret_receiver = kem.decap_secret(ciphertext)
    
    # Verify shared secrets match
    assert shared_secret_sender == shared_secret_receiver
    
    print(f"Public key size: {len(public_key)} bytes")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Shared secret size: {len(shared_secret_sender)} bytes")

# ML-DSA (Dilithium) Signatures
def dilithium_example():
    # Create signature object
    sig = oqs.Signature("Dilithium3")
    
    # Generate keypair
    public_key = sig.generate_keypair()
    
    # Sign message
    message = b"This is a test message"
    signature = sig.sign(message)
    
    # Verify signature
    is_valid = sig.verify(message, signature, public_key)
    
    print(f"Public key size: {len(public_key)} bytes")
    print(f"Signature size: {len(signature)} bytes")
    print(f"Verification: {is_valid}")

if __name__ == "__main__":
    kyber_example()
    dilithium_example()
```

### C with liboqs

```c
#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>

int main() {
    // ML-KEM (Kyber) example
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM\n");
        return 1;
    }
    
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_sender = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_receiver = malloc(kem->length_shared_secret);
    
    // Generate keypair
    OQS_KEM_keypair(kem, public_key, secret_key);
    
    // Encapsulate
    OQS_KEM_encaps(kem, ciphertext, shared_secret_sender, public_key);
    
    // Decapsulate
    OQS_KEM_decaps(kem, shared_secret_receiver, ciphertext, secret_key);
    
    // Verify
    if (memcmp(shared_secret_sender, shared_secret_receiver, 
               kem->length_shared_secret) == 0) {
        printf("Shared secrets match!\n");
    }
    
    // Cleanup
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_sender);
    free(shared_secret_receiver);
    OQS_KEM_free(kem);
    
    return 0;
}
```

### Go with circl

```go
package main

import (
    "fmt"
    "github.com/cloudflare/circl/kem/kyber/kyber768"
    "github.com/cloudflare/circl/sign/dilithium/mode3"
)

func kyberExample() {
    // Generate keypair
    pk, sk := kyber768.GenerateKeyPair(nil)
    
    // Encapsulate
    ct, ss_sender, err := kyber768.EncapsulateTo(nil, nil, pk)
    if err != nil {
        panic(err)
    }
    
    // Decapsulate
    ss_receiver, err := kyber768.DecapsulateTo(nil, sk, ct)
    if err != nil {
        panic(err)
    }
    
    // Verify
    fmt.Printf("Shared secrets match: %v\n", 
        string(ss_sender) == string(ss_receiver))
}

func dilithiumExample() {
    // Generate keypair
    pk, sk, err := mode3.GenerateKey(nil)
    if err != nil {
        panic(err)
    }
    
    // Sign message
    message := []byte("Test message")
    signature := mode3.SignTo(nil, sk, message)
    
    // Verify signature
    valid := mode3.Verify(pk, message, signature)
    fmt.Printf("Signature valid: %v\n", valid)
}

func main() {
    kyberExample()
    dilithiumExample()
}
```

### Java with Bouncy Castle PQC

```java
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import javax.crypto.KeyGenerator;
import java.security.*;

public class PQCExample {
    static {
        Security.addProvider(new BouncyCastlePQCProvider());
    }
    
    public static void kyberExample() throws Exception {
        // Generate Kyber keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber768);
        KeyPair keyPair = kpg.generateKeyPair();
        
        System.out.println("Kyber768 keypair generated");
        System.out.println("Public key size: " + 
            keyPair.getPublic().getEncoded().length);
    }
    
    public static void dilithiumExample() throws Exception {
        // Generate Dilithium keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        KeyPair keyPair = kpg.generateKeyPair();
        
        // Sign message
        Signature signer = Signature.getInstance("Dilithium", "BCPQC");
        signer.initSign(keyPair.getPrivate());
        byte[] message = "Test message".getBytes();
        signer.update(message);
        byte[] signature = signer.sign();
        
        // Verify signature
        Signature verifier = Signature.getInstance("Dilithium", "BCPQC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        boolean valid = verifier.verify(signature);
        
        System.out.println("Signature valid: " + valid);
    }
    
    public static void main(String[] args) throws Exception {
        kyberExample();
        dilithiumExample();
    }
}
```

## Testing and Validation

### Performance Testing

```python
import time
import oqs

def benchmark_kem(alg_name, iterations=1000):
    kem = oqs.KeyEncapsulation(alg_name)
    
    # Key generation
    start = time.time()
    for _ in range(iterations):
        public_key = kem.generate_keypair()
    keygen_time = (time.time() - start) / iterations
    
    public_key = kem.generate_keypair()
    
    # Encapsulation
    start = time.time()
    for _ in range(iterations):
        ciphertext, shared_secret = kem.encap_secret(public_key)
    encap_time = (time.time() - start) / iterations
    
    # Decapsulation
    ciphertext, _ = kem.encap_secret(public_key)
    start = time.time()
    for _ in range(iterations):
        shared_secret = kem.decap_secret(ciphertext)
    decap_time = (time.time() - start) / iterations
    
    print(f"{alg_name}:")
    print(f"  Key generation: {keygen_time*1000:.2f} ms")
    print(f"  Encapsulation:  {encap_time*1000:.2f} ms")
    print(f"  Decapsulation:  {decap_time*1000:.2f} ms")
    print(f"  Public key:     {len(public_key)} bytes")
    print(f"  Ciphertext:     {len(ciphertext)} bytes\n")

# Benchmark different algorithms
benchmark_kem("Kyber512")
benchmark_kem("Kyber768")
benchmark_kem("Kyber1024")
```

### Interoperability Testing

```bash
# Test with multiple implementations
# 1. Generate keys with liboqs
# 2. Exchange with Bouncy Castle
# 3. Verify with circl

# Test vector validation
# Download NIST test vectors
# Verify implementation matches expected results
```

### Security Testing

```bash
# Side-channel analysis
# Memory usage analysis
# Timing attack resistance
# Fault injection resistance

# Use tools:
# - Valgrind for memory leaks
# - timing attack frameworks
# - Side-channel analysis tools
```

## Timeline and Roadmap

### 2025 (NOW)

- [x] NIST standards finalized
- [ ] Begin inventory of cryptographic assets
- [ ] Update cryptographic libraries
- [ ] Test hybrid implementations
- [ ] Deploy PQC in non-critical systems

### 2026-2027

- [ ] Migrate high-priority systems
- [ ] Update TLS/SSL infrastructure
- [ ] Renew certificates with PQC support
- [ ] Deploy hybrid solutions widely
- [ ] Train staff on PQC

### 2028-2029

- [ ] Migrate medium-priority systems
- [ ] Begin deprecating classical algorithms
- [ ] Full PQC support in all new systems
- [ ] Regular security audits
- [ ] Monitor quantum computing progress

### 2030+

- [ ] Complete migration
- [ ] Deprecate RSA/ECC entirely
- [ ] Continuous monitoring and updates
- [ ] Adapt to new threats
- [ ] Stay current with standards

## Additional Resources

### Official Standards

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [FIPS 204 - ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [FIPS 205 - SLH-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)

### Implementation Libraries

- [liboqs - Open Quantum Safe](https://github.com/open-quantum-safe/liboqs)
- [oqs-provider - OpenSSL integration](https://github.com/open-quantum-safe/oqs-provider)
- [Bouncy Castle PQC](https://www.bouncycastle.org/java.html)
- [PQClean - Clean implementations](https://github.com/PQClean/PQClean)
- [Cloudflare circl](https://github.com/cloudflare/circl)

### Tools and Testing

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [PQC Implementation Study Group](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Quantum Resistant Ledger](https://www.theqrl.org/)

### Further Reading

- [RFC 9180 - Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [NIST IR 8413 - Status Report on PQC](https://doi.org/10.6028/NIST.IR.8413)
- [BSI TR-02102-1 - Cryptographic Mechanisms (German)](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html)

