# Cryptographic Algorithms
Let's go over the most common encryption and hashing algorithms, and compare them.

## Hashing Algorithms
The folloing table that compares some of the most well-known hashing algorithms, along with an indication of whether they are considered to be post-quantum resistant.

| Algorithm Name | Output Size (bits) | Cryptographic | Post-Quantum Ready |
|----------------|--------------------|---------------|-------------------|
| MD5            | 128                | Yes           | No                |
| SHA-1          | 160                | Yes           | No                |
| SHA-256        | 256                | Yes           | No                |
| SHA-3          | 224, 256, 384, 512 | Yes           | Yes (believed to) |
| BLAKE2         | 256, 512           | Yes           | Yes (believed to) |



1. **MD5**: An older cryptographic hash function that produces a 128-bit hash value. It is no longer considered secure against well-funded attackers.
2. **SHA-1**: A cryptographic hash function that produces a 160-bit hash value. It is no longer considered secure against well-funded attackers.
3. **SHA-256**: A member of the SHA-2 family, it produces a 256-bit hash value and is currently considered secure.
4. **SHA-3**: The latest member of the Secure Hash Algorithm family, it allows for variable output sizes and is believed to be secure against quantum attacks.
5. **BLAKE2**: A cryptographic hash function that is faster than MD5, SHA-1, and SHA-256, and is believed to be secure against quantum attacks.

The "Post-Quantum Ready" column is based on current beliefs and knowledge, and the landscape of cryptography is always evolving, especially with the advent of quantum computing. It is recommended to stay updated with the latest research and guidelines from organizations like the [National Institute of Standards and Technology (NIST) for the most accurate information](https://csrc.nist.gov/projects/post-quantum-cryptography).


### HMAC (Hash-Based Message Authentication Code) Implementations and Post-Quantum Readiness

| HMAC Implementation | Description                                                                                      | Post-Quantum Ready (PQR)  |
|---------------------|--------------------------------------------------------------------------------------------------|---------------------------|
| HMAC-MD5            | Uses the MD5 hash function. It is not recommended for further use as MD5 is considered broken.  | No                        |
| HMAC-SHA1           | Utilizes the SHA-1 hash function. Considered weak due to vulnerabilities in SHA-1.              | No                        |
| HMAC-SHA256         | Based on the SHA-256 function, part of the SHA-2 family. Currently considered secure.            | Possibly                  |
| HMAC-SHA3           | Uses the SHA-3 hash function, which is currently considered secure and resistant to quantum attacks. | Yes (believed to be)      |
| HMAC-BLAKE2         | Implemented with the BLAKE2 hash function, believed to be secure and potentially resistant to quantum attacks. | Yes (believed to be)      |


## Encryption Algorithms


| Algorithm Name                | Key Size (bits) | Type        | Post-Quantum Ready |
|-------------------------------|-----------------|-------------|-------------------|
| AES-128                       | 128             | Symmetric   | No                |
| AES-256                       | 256             | Symmetric   | No                |
| RSA                           | 1024, 2048, 3072, 4096 | Asymmetric | No            |
| ECC                           | 224, 256, 384, 521 | Asymmetric | No                |
| Lattice-Based Cryptography    | Variable        | Asymmetric  | Yes               |
| Hash-Based Cryptography       | Variable        | Asymmetric  | Yes               |
| Code-Based Cryptography       | Variable        | Asymmetric  | Yes               |



1. **AES-128 / AES-256**: Advanced Encryption Standard, a symmetric encryption algorithm with key sizes of 128 and 256 bits respectively. Not considered post-quantum secure.
   
2. **RSA**: An asymmetric encryption algorithm that uses a pair of keys (public and private). The security is based on the difficulty of factoring large composite numbers. Not considered post-quantum secure.

3. **ECC (Elliptic Curve Cryptography)**: An asymmetric encryption algorithm that uses elliptic curves over finite fields. Not considered post-quantum secure.
   
4. **Lattice-Based Cryptography**: A type of asymmetric encryption that is considered to be post-quantum secure. It is based on the hardness of certain problems in lattice theory.
   
5. **Hash-Based Cryptography**: A type of asymmetric encryption that is considered to be post-quantum secure. It utilizes cryptographic hash functions.

6. **Code-Based Cryptography**: A type of asymmetric encryption that is considered to be post-quantum secure. It is based on the hardness of decoding linear codes.



### Cryptographic Algorithms Explanation

| Cryptographic Algorithm       | Description                                                                                                                                                        | Examples                     | Post-Quantum Ready |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|-------------------|
| **Lattice-Based Cryptography**| These algorithms rely on the hardness of lattice problems, including the Shortest Vector Problem (SVP) and Learning With Errors (LWE). They are believed to offer resistance against quantum attacks due to the mathematical problems they are based on, which have not yet been solved efficiently using quantum algorithms. | NTRU, Kyber, Saber | Yes               |
| **Hash-Based Cryptography**   | These algorithms use cryptographic hash functions as a fundamental building block. They are considered to be secure against quantum attacks as they rely on the hardness of preimage and collision resistance properties of hash functions.                                     | SPHINCS, LMS        | Yes               |
| **Code-Based Cryptography**   | These algorithms are based on the theory of error-correcting codes. They rely on the difficulty of decoding a general linear code, which is considered to be a hard problem even for quantum computers.                                                        | McEliece, Niederreiter   | Yes               |


### AES Modes and Post-Quantum Readiness

| AES Mode        | Description                                                              | Post-Quantum Ready |
|-----------------|--------------------------------------------------------------------------|--------------------|
| AES-CBC         | Cipher Block Chaining mode, where each block is XORed with the previous ciphertext block before being encrypted. | No                 |
| AES-GCM         | Galois/Counter Mode, an authenticated encryption with associated data (AEAD) scheme. It combines the counter mode of encryption with the Galois mode of authentication. | ?                 |
| AES-CCM         | Counter with CBC-MAC, another authenticated encryption scheme combining counter mode encryption with a CBC-MAC based authentication. | No                 |
| AES-CTR         | Counter Mode, where plaintext blocks are XORed with an encrypted counter value. The counter is incremented for each subsequent block. | No                 |
| AES-OFB         | Output Feedback Mode, turns a block cipher into a synchronous stream cipher. It generates keystream blocks, which are then XORed with the plaintext blocks to get the ciphertext. | No                 |
| AES-CFB         | Cipher Feedback Mode, turns a block cipher into a self-synchronizing stream cipher. Operation is very similar to CBC mode, but CFB mode operates on smaller units (bits or bytes instead of blocks). | No                 |
| AES-XTS         | XEX-based Tweaked CodeBook mode with ciphertext Stealing, mainly used for disk encryption. | No                 |
| AES-KW          | Key Wrap, used for wrapping keys with AES encryption. | No                 |


### AES Key Lengths and Post-Quantum Readiness

| AES Variant | Key Length (bits) | Post-Quantum Ready (PQR) |
|-------------|-------------------|--------------------------|
| AES-128     | 128               | Possibly (with increased key size) |
| AES-192     | 192               | Possibly (with increased key size) |
| AES-256     | 256               | Possibly (with increased key size) |



## Additional References
Again, I must emphasize that the field of post-quantum cryptography is evolving, and it is recommended to stay updated with the latest research and guidelines from NIST.
- NIST Post-Quantum Cryptography Project: https://csrc.nist.gov/projects/post-quantum-cryptography
- Post Quantum Cryptography (Wikipedia): https://en.wikipedia.org/wiki/Post-quantum_cryptography
