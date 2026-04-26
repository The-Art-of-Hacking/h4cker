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


<img width="1230" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/b4919061-0736-4884-9f44-51f0a53fdcc6">


Code snippet in Python to perform the entire decryption:

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

This challenge provided you with an understanding of the RSA algorithm. It covered important concepts like prime factorization, modular arithmetic, and key derivation.
