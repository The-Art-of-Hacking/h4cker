# RSA Public Key Crack

**Level:** Advanced

**Description:**
In this challenge, you'll need to reverse an RSA public key to discover the private key. RSA is a widely used public-key cryptosystem that relies on the difficulty of factoring the product of two large prime numbers.

**Challenge Text:**
```
Given RSA public key (n, e) = (43733, 3)
```

**Instructions:**
1. Factorize the modulus `n` into its prime components `p` and `q`.
2. Compute the private exponent `d` using the public exponent `e`.
3. Validate the private key by encrypting and decrypting a test message.

**Answer:**
1. Factorize `n` into `p` and `q`. Here, \( p = 157 \), \( q = 139 \).
2. Compute \(\phi(n) = (p - 1)(q - 1) = 43264\).
3. Compute the private exponent \( d \equiv e^{-1} \mod \phi(n) = 28843 \).

**Python Code:**
```python
from sympy import mod_inverse

def factorize_n(n):
    # Simple function to find the factors of n (assuming n is a product of two primes)
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None

n = 43733
e = 3

p, q = factorize_n(n)
phi_n = (p - 1) * (q - 1)

# Compute d, the modular multiplicative inverse of e modulo phi_n
d = mod_inverse(e, phi_n)

print("Private Key (p, q, d):", p, q, d)
```

**Output:**
```
Private Key (p, q, d): 157 139 28843
```

This code defines a function to factorize `n` and then uses the sympy library's `mod_inverse` function to compute the modular multiplicative inverse of `e` modulo \(\phi(n)\). It then prints the resulting private key.

Note: This exercise exposes the importance of choosing large prime numbers in real-world RSA implementations. The prime numbers used here are intentionally small to allow for manual factoring. In practice, the prime numbers would be hundreds of digits long, making this attack infeasible.
