# Cryptographic Algorithms (2025 Edition)

This section summarizes current and emerging cryptographic standards, their quantum resistance, and migration guidance for modern security.

## Current Standards

### Public Key Encryption & Key Exchange

| Algorithm           | Status                    | Post-Quantum Ready |
|---------------------|---------------------------|--------------------|
| RSA                 | Deprecated: quantum-vulnerable | No                |
| ECC/ECDSA           | Deprecated: quantum-vulnerable | No                |
| Diffie-Hellman      | Deprecated: quantum-vulnerable | No                |
| ML-KEM (CRYSTALS-Kyber) | Approved (FIPS 203)    | Yes               |
| HQC (Hamming Quasi-Cyclic) | Selected (2025)      | Yes               |

### Digital Signatures

| Algorithm           | Status                    | Post-Quantum Ready |
|---------------------|--------------------------|--------------------|
| RSA Signatures      | Deprecated: quantum-vulnerable | No            |
| ECDSA, EdDSA, DSA   | Deprecated: quantum-vulnerable | No            |
| SLH-DSA (SPHINCS+)  | Approved (FIPS 205)      | Yes               |
| ML-DSA (CRYSTALS-Dilithium) | Approved (FIPS 204) | Yes               |
| FALCON              | Selected for standardization | Yes            |

***

## Symmetric Algorithms

Symmetric crypto is less affected by quantum computers, but key/output sizes must be larger to compensate for Grover’s algorithm.

| Algorithm | Status   | Post-Quantum Ready | Notes                                  |
|-----------|----------|-------------------|----------------------------------------|
| AES-256   | Active   | Yes*              | Use longer keys (min. 256 bits)        |
| AES-128   | Avoid    | No                | Insufficient against Grover’s algorithm|
| SHA-2     | Active   | Yes*              | Use ≥256-bit output, SHA-512 preferred |
| SHA-1     | Avoid    | No                | Collision-prone, quantum-vulnerable    |
| SHA-3     | Active   | Yes*              | Use ≥256-bit output                    |

*Symmetric algorithms are quantum-resistant with large enough keys/output sizes, but quantum computers halve the effective security strength. Migrate away from AES-128 and SHA-1.

***

## Algorithms To Avoid (Do Not Use For New Deployments)

- **RSA (encryption/signatures)**
- **ECC/ECDSA/EdDSA** (incl. Ed25519, Curve25519)
- **Diffie-Hellman** (including DH key exchanges)
- **DSA/ElGamal**
- **SHA-1** (all uses)
- **AES-128** (upgrade to AES-256)
- Any legacy protocol not listed in the “Approved” section

These are **deprecated** due to quantum vulnerability. Do not deploy or rely on for long-term data protection.

***

## Migration Guidance

- Start transitioning public-key infrastructure to Kyber, Dilithium, SPHINCS+, and Falcon as finalized by NIST standards (FIPS 203, 204, 205).
- Use AES-256 for symmetric encryption and SHA-2/SHA-3 (≥256 bits) for hashing.
- Regularly follow NIST updates: https://csrc.nist.gov/projects/post-quantum-cryptography
- For transitional environments, hybrid schemes (classical + post-quantum) may be used until the migration is complete.

***

## Additional References

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Cisco Blog about PQC](https://blogs.cisco.com/developer/how-post-quantum-cryptography-affects-security-and-encryption-algorithms)
- [Post Quantum Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography) (Wikipedia)
- [Information Week Podcast](https://www.youtube.com/watch?v=GvkCrSqSn5g)
