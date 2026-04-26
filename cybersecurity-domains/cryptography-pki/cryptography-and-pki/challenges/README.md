# Cryptography Challenges

> **Hands-on cryptography puzzles designed to build your skills from classical ciphers to modern cryptographic attacks**

## Welcome

Welcome to the fascinating world of cryptography! Cryptography is more than just codes and ciphers; it's the backbone of secure communication. This series of challenges is designed to engage you in hands-on practice, enhance your understanding, and ignite your curiosity in cryptography through practical exercises with sample code.

In these challenges, you will explore different aspects of cryptography, from historical ciphers to modern cryptographic algorithms, and learn about common vulnerabilities and attacks.

## 🎯 Learning Objectives

### 1. Classical Cryptography
Uncover the secrets of historical ciphers and understand the foundations of cryptographic thinking.
- Caesar and substitution ciphers
- Vigenère polyalphabetic cipher
- Frequency analysis techniques
- Cryptanalysis methods

### 2. Public Key Cryptography
Dive into modern cryptosystems and understand asymmetric encryption.
- RSA encryption and signatures
- Elliptic Curve Cryptography (ECC)
- Key pair generation and validation
- Public/private key relationships

### 3. Cryptographic Attacks
Understand the importance of strong parameters and how weak implementations can be exploited.
- Weak key attacks
- Factorization techniques
- Digital signature forgery
- Side-channel considerations

### 4. Key Exchange Protocols
Explore how keys are securely exchanged between parties.
- Diffie-Hellman key exchange
- Man-in-the-middle prevention
- Secure parameter selection
- Protocol implementation

## 📊 Challenge Levels

### 🟢 Beginner Level
**Prerequisites:** Basic programming knowledge, curiosity about cryptography  
**Time per challenge:** 15-30 minutes  
**Skills:** Pattern recognition, basic math, code reading

### 🟡 Intermediate Level
**Prerequisites:** Understanding of number theory, modular arithmetic  
**Time per challenge:** 30-60 minutes  
**Skills:** Mathematical analysis, algorithm implementation, cryptanalysis

### 🔴 Advanced Level
**Prerequisites:** Strong mathematical background, cryptography fundamentals  
**Time per challenge:** 60-120 minutes  
**Skills:** Advanced cryptanalysis, exploitation techniques, deep understanding of protocols

## 📋 Available Challenges

### Beginner Challenges (🟢)

#### 1. Classic Caesar Cipher
**[Challenge 1: Caesar Cipher](./01_Classic_Caesar_Cipher.md)**

**Objective:** Decrypt a message encrypted with the Caesar cipher  
**Skills:** Pattern recognition, frequency analysis basics  
**Techniques:** Brute force, character frequency analysis  

**What You'll Learn:**
- How substitution ciphers work
- Basic cryptanalysis techniques
- Python implementation for automated cracking

---

#### 4. Classic Vigenère Cipher
**[Challenge 4: Vigenère Cipher](./04_Classic_Vigenere_Cipher.md)**

**Objective:** Decrypt a Vigenère cipher using a known keyword  
**Skills:** Polyalphabetic cipher understanding  
**Techniques:** Key repetition, modular arithmetic  

**What You'll Learn:**
- How polyalphabetic ciphers improve upon simple substitution
- Key-based encryption and decryption
- Implementation of classical algorithms

---

### Intermediate Challenges (🟡)

#### 2. Diffie-Hellman Key Exchange (Basic)
**[Challenge 2: Diffie-Hellman Basics](./02_Diffie_Hellman_Key_Exchange.md)**

**Objective:** Simulate the Diffie-Hellman key exchange algorithm  
**Skills:** Modular arithmetic, key exchange protocols  
**Techniques:** Discrete logarithm problem, shared secret derivation  

**What You'll Learn:**
- How two parties establish a shared secret over an insecure channel
- The mathematical foundation of key exchange
- RSA and modular arithmetic fundamentals

---

#### 5. Implement Diffie-Hellman Key Exchange
**[Challenge 5: Diffie-Hellman Implementation](./05_Implement_Diffie_Hellman_Key_Exchange.md)**

**Objective:** Compute and validate public keys using Diffie-Hellman  
**Skills:** Protocol implementation, parameter validation  
**Techniques:** Safe prime selection, generator validation  

**What You'll Learn:**
- Complete Diffie-Hellman implementation from scratch
- Importance of proper parameter selection
- Security considerations in key exchange protocols

---

#### 7. Frequency Analysis Attack on Substitution Cipher
**[Challenge 7: Frequency Analysis](./07_Frequency_Analysis_Attack_Substitution.md)**

**Objective:** Decrypt a substitution cipher using frequency analysis  
**Skills:** Statistical cryptanalysis, pattern recognition  
**Techniques:** Letter frequency distribution, bigram/trigram analysis  

**What You'll Learn:**
- How to perform statistical cryptanalysis
- English language letter frequency patterns
- Automated cryptanalysis techniques

---

#### 8. Elliptic Curve Key Pair Generation
**[Challenge 8: ECC Key Generation](./08_Elliptic_Curve_Key_Pair_Generation.md)**

**Objective:** Generate and validate an elliptic curve key pair  
**Skills:** Elliptic curve mathematics, point operations  
**Techniques:** Scalar multiplication, point validation  

**What You'll Learn:**
- How elliptic curve cryptography works
- ECC advantages over RSA
- Key generation and validation procedures
- ⚠️ Note: ECC is quantum-vulnerable, but still important to understand

---

### Advanced Challenges (🔴)

#### 3. Digital Signature Forgery (Basic)
**[Challenge 3: Signature Forgery Basics](./03_Digital_Signature_Forgery.md)**

**Objective:** Forge a digital signature for a given message  
**Skills:** Digital signature schemes, vulnerability analysis  
**Techniques:** Weak parameter exploitation  

**What You'll Learn:**
- How digital signatures work
- Common implementation vulnerabilities
- Importance of proper parameter selection

---

#### 6. Digital Signature Forgery (Advanced)
**[Challenge 6: Advanced Signature Forgery](./06_Digital_Signature_Forgery_Advanced.md)**

**Objective:** Forge a digital signature exploiting RSA weaknesses  
**Skills:** RSA internals, number theory, attack methodology  
**Techniques:** Factorization, chosen plaintext attacks  

**What You'll Learn:**
- Deep RSA vulnerabilities
- Advanced attack techniques
- Why RSA is deprecated for post-quantum era

---

#### 9. Attack on Weak RSA Modulus
**[Challenge 9: RSA Attack](./09_Attack_on_Weak_RSA_Modulus.md)**

**Objective:** Determine the private key of an RSA system with weak parameters  
**Skills:** Factorization algorithms, RSA mathematics  
**Techniques:** Prime factorization, key derivation  

**What You'll Learn:**
- How RSA encryption works mathematically
- Why key size matters critically
- Practical factorization techniques
- RSA vulnerability to quantum computers

---

## 🚀 Getting Started

### Recommended Learning Path

**Path 1: Complete Beginner**
```
1. Caesar Cipher (Challenge 1)
   ↓
2. Vigenère Cipher (Challenge 4)
   ↓
3. Frequency Analysis (Challenge 7)
   ↓
4. Diffie-Hellman Basics (Challenge 2)
```

**Path 2: Public Key Focus**
```
1. Diffie-Hellman Basics (Challenge 2)
   ↓
2. Implement Diffie-Hellman (Challenge 5)
   ↓
3. Elliptic Curve Keys (Challenge 8)
   ↓
4. RSA Attack (Challenge 9)
```

**Path 3: Cryptanalysis Focus**
```
1. Caesar Cipher (Challenge 1)
   ↓
2. Frequency Analysis (Challenge 7)
   ↓
3. Digital Signature Forgery (Challenge 3)
   ↓
4. Advanced Forgery (Challenge 6)
   ↓
5. RSA Attack (Challenge 9)
```

### Prerequisites

**For All Challenges:**
- Basic programming skills (Python recommended)
- Text editor or IDE
- Terminal/command line familiarity

**For Intermediate/Advanced:**
- Understanding of modular arithmetic
- Basic number theory
- Algorithm analysis skills

### Tools and Resources

**Recommended Tools:**
- Python 3.x with cryptography libraries
- Jupyter Notebooks (optional, for experimentation)
- Online tools: CyberChef, dcode.fr
- Calculator for large number arithmetic

**Helpful Resources:**
- [Cryptography and Network Security - Forouzan](https://www.mhhe.com/forouzan)
- [Applied Cryptography - Schneier](https://www.schneier.com/books/applied-cryptography/)
- [Cryptography Stack Exchange](https://crypto.stackexchange.com/)

## 📝 Challenge Format

Each challenge includes:

1. **Objective**: What you need to accomplish
2. **Challenge Text**: The encrypted data or scenario
3. **Instructions**: Step-by-step guidance
4. **Answer Section**: Solution and explanation
5. **Code Examples**: Working implementations
6. **Learning Notes**: Key concepts explained

## 🏆 Completion Tracker

Track your progress:

- [ ] Challenge 1: Classic Caesar Cipher
- [ ] Challenge 2: Diffie-Hellman Key Exchange (Basic)
- [ ] Challenge 3: Digital Signature Forgery (Basic)
- [ ] Challenge 4: Classic Vigenère Cipher
- [ ] Challenge 5: Implement Diffie-Hellman Key Exchange
- [ ] Challenge 6: Digital Signature Forgery (Advanced)
- [ ] Challenge 7: Frequency Analysis Attack
- [ ] Challenge 8: Elliptic Curve Key Pair Generation
- [ ] Challenge 9: Attack on Weak RSA Modulus

## 💡 Tips for Success

1. **Start Simple**: Begin with beginner challenges even if experienced
2. **Understand Before Coding**: Read theory before implementing
3. **Experiment**: Modify parameters and observe results
4. **Document**: Keep notes on what you learn
5. **Compare Solutions**: After solving, compare with provided solutions
6. **Ask Questions**: Use forums and communities when stuck
7. **Practice**: Repetition builds understanding

## ⚠️ Ethical Considerations

**Important Reminders:**

- These challenges are for **educational purposes only**
- Understanding attacks helps build better defenses
- Never use these techniques on systems without authorization
- Respect intellectual property and privacy
- Follow responsible disclosure practices

**Legal Notice:** Unauthorized access to computer systems is illegal in most jurisdictions. Always obtain proper authorization before testing security.

## 🔗 Related Resources

### From This Repository
- [Cryptography Algorithms Reference](../crypto_algorithms.md)
- [Hands-On Labs](../labs/)
- [Quick Reference Cheat Sheets](../quick-reference/)
- [Practical Tutorials](../tutorials/)

### External Resources
- [CryptoHack](https://cryptohack.org/) - More cryptography challenges
- [Cryptopals](https://cryptopals.com/) - Crypto challenges
- [OverTheWire Crypto](https://overthewire.org/) - Wargames

## 🎓 After Completing Challenges

Once you've completed these challenges, consider:

1. **Advanced Labs**: Move to the [hands-on labs](../labs/) for infrastructure practice
2. **Real Implementations**: Study production cryptography libraries
3. **CTF Competitions**: Participate in capture-the-flag events
4. **Contribute**: Share your solutions and help others learn
5. **Research**: Explore current cryptography research papers
6. **Post-Quantum**: Study the [Post-Quantum Migration Guide](../tutorials/post-quantum-migration.md)

## 📚 Further Learning

**Next Steps:**
- Complete all challenges in your chosen path
- Explore [Labs](../labs/) for infrastructure practice
- Study [Post-Quantum Cryptography](../tutorials/post-quantum-migration.md)
- Read [PKI Fundamentals](../tutorials/pki-fundamentals.md)
- Practice with real-world tools from [Crypto Tools](../crypto_tools.md)

**Happy Hacking! 🔐**

Remember: Understanding how cryptographic systems can be broken is essential to building secure systems.

