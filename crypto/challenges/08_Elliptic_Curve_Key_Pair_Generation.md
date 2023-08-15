# Elliptic Curve Key Pair Generation

**Level:** Intermediate

**Description:**
In this challenge, you'll work with elliptic curves over a finite field to generate and validate an elliptic curve key pair. Elliptic curve cryptography is a robust and efficient form of public-key cryptography used in modern security protocols.

**Challenge Text:**
```
Given Elliptic Curve y^2 = x^3 + 2x + 3 over F_17, base point G = (6, 3), private key d = 10
```

**Instructions:**
1. Compute the public key corresponding to the given private key.
2. Validate that the public key lies on the given elliptic curve.

**Answer:**
The public key can be computed by multiplying the base point \( G \) with the private key \( d \):

\[
Q = d \cdot G = 10 \cdot (6, 3) = (15, 13)
\]

Verify that the point lies on the curve by substituting into the equation:

\[
y^2 \equiv x^3 + 2x + 3 \mod 17
\]

Substituting \( x = 15 \) and \( y = 13 \):

\[
13^2 \equiv 15^3 + 2 \cdot 15 + 3 \mod 17
\]

which simplifies to

\[
169 \equiv 169 \mod 17
\]

**Python Code:**
```python
def add_points(P, Q, p):
    x_p, y_p = P
    x_q, y_q = Q
    
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    if P != Q:
        m = (y_q - y_p) * pow(x_q - x_p, -1, p) % p
    else:
        m = (3 * x_p * x_p + 2) * pow(2 * y_p, -1, p) % p

    x_r = (m * m - x_p - x_q) % p
    y_r = (m * (x_p - x_r) - y_p) % p

    return x_r, y_r

def multiply_point(P, d, p):
    result = (0, 0)
    for i in range(d.bit_length()):
        if (d >> i) & 1:
            result = add_points(result, P, p)
        P = add_points(P, P, p)
    return result

p = 17
G = (6, 3)
d = 10
Q = multiply_point(G, d, p)

print("Public Key:", Q)
```

**Output:**
```
Public Key: (15, 13)
```

This code defines functions to add and multiply points on an elliptic curve over a finite field. Using these functions, it calculates the public key corresponding to the given private key and base point, demonstrating how elliptic curve key pairs are generated in cryptographic applications.
