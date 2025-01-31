# Cryptographic Algorithms
Let's go over the most common encryption and hashing algorithms, and compare them.

Based on the search results and NIST's announcements, here is the status of cryptographic standards and their quantum resistance:

## Current Standards

**Public Key Encryption & Key Exchange**
| Algorithm | Status | Post-Quantum Ready |
|-----------|---------|-------------------|
| RSA | Active but vulnerable | No |
| ECC/ECDSA | Active but vulnerable | No |
| ML-KEM (CRYSTALS-Kyber) | Approved | Yes |

**Digital Signatures**
| Algorithm | Status | Post-Quantum Ready |
|-----------|---------|-------------------|
| RSA Signatures | Active but vulnerable | No |
| ECDSA | Active but vulnerable | No |
| SLH-DSA (SPHINCS+) | Approved | Yes |

## Future Standards

**Additional Post-Quantum Algorithms**
| Algorithm | Status | Type |
|-----------|---------|------|
| FIPS 204 (Dilithium) | In development | Digital Signature |
| FIPS 205 (SPHINCS+) | In development | Digital Signature |
| FALCON | Selected | Digital Signature |

## Symmetric Algorithms
| Algorithm | Status | Post-Quantum Ready | Notes |
|-----------|---------|-------------------|--------|
| AES-256 | Active | Yes* | Requires larger key sizes |
| SHA-2 | Active | Yes* | Requires larger output sizes |
| SHA-3 | Active | Yes* | Requires larger output sizes |

*Note: Symmetric algorithms are considered quantum-resistant when using sufficiently large key/output sizes, though they may need larger parameters to maintain the same security level against quantum attacks.

The transition to post-quantum cryptography represents a major shift in cryptographic standards to protect against future quantum computer threats. You are encouraged to begin planning for migration to these new algorithms while maintaining current standards during the transition period.




## Additional References
Again, I must emphasize that the field of post-quantum cryptography is evolving, and it is recommended to stay updated with the latest research and guidelines from NIST.
- NIST Post-Quantum Cryptography Project: https://csrc.nist.gov/projects/post-quantum-cryptography
- Post Quantum Cryptography (Wikipedia): https://en.wikipedia.org/wiki/Post-quantum_cryptography
- Information Week Podcast: https://www.youtube.com/watch?v=GvkCrSqSn5g
