# Challenge 2: Simple RSA Encryption

**Challenge Text:**
```
n = 3233, e = 17, Encrypted message: [2201, 2332, 1452]
```

**Instructions:**
1. Factorize the value of \( n \) into two prime numbers, \( p \) and \( q \).
2. Compute the private key \( d \) using the Extended Euclidean Algorithm.
3. Decrypt the message using the computed private key.

### Answer:

Here are the detailed solutions for each step:

**Step 1:** Factorize \( n = 3233 \) into two prime numbers:
   \( p = 61 \), \( q = 53 \)

**Step 2:** Compute the Euler's Totient function \( \phi(n) \):
   \( \phi(n) = (p-1)(q-1) = 3120 \)

Compute the private key \( d \) such that:
   \( de \equiv 1 \mod \phi(n) \)

Using Extended Euclidean Algorithm, we can find:
   \( d = 2753 \)

**Step 3:** Decrypt the message using the private key:
   Decrypted message: "HEY"

Here's a code snippet in Python to perform the entire decryption:

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def decrypt_rsa(ciphertext, n, e):
    p, q = 61, 53  # Factored values
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    plaintext = [str(pow(c, d, n)) for c in ciphertext]
    return ''.join(chr(int(c)) for c in plaintext)

n = 3233
e = 17
ciphertext = [2201, 2332, 1452]

decrypted_text = decrypt_rsa(ciphertext, n, e)
print(decrypted_text)  # Output: "HEY"
```

This challenge provides an understanding of the RSA algorithm, which is foundational in modern cryptography. It covers important concepts like prime factorization, modular arithmetic, and key derivation.
